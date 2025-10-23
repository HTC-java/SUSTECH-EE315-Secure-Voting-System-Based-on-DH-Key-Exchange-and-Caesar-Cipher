import socket
import threading
from collections import defaultdict
import random  


def generate_private_key():
    return random.randint(1, 100)


def generate_public_key(private_key, p=23, g=5):
    return (g ** private_key) % p


def generate_shared_secret(their_public_key, private_key, p=23):
    shared = (their_public_key ** private_key) % p
    return shared % 26  # 凯撒偏移量限制在0-25


def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


def add_checksum(msg):
    checksum = sum(ord(c) for c in msg[:3]) % 100
    return f"{checksum:02d}_{msg}"


def verify_checksum(msg_with_checksum):
    if "_" not in msg_with_checksum:
        return False, ""
    checksum_str, raw_msg = msg_with_checksum.split("_", 1)
    actual_checksum = sum(ord(c) for c in raw_msg[:3]) % 100
    return int(checksum_str) == actual_checksum, raw_msg

CRLF = "\r\n"
END = "END"
ACK = "ACK"
NACK = "NACK"
HOST = "127.0.0.1"
PORT = 18080

candidates = ["Bob", "Alice"]
votes = defaultdict(int)
lock = threading.Lock()
client_connections = []  # 存储客户端连接和对应的共享密钥
voting_ended = False


def broadcast_results():
    """计算并广播加密的投票结果"""
    with lock:
        total = sum(votes.values())
        if total == 0:
            result_lines = [
                "VOTE_RESULTS",
                "Status: No votes received",
                f"Total Votes: {total}",
                END
            ]
        else:
            max_votes = max(votes.values())
            winners = [name for name, cnt in votes.items() if cnt == max_votes]
            result_lines = [
                               "VOTE_RESULTS",
                               f"Total Votes: {total}",
                               "--- Detailed Counts ---"
                           ] + [f"{c}: {votes[c]} votes" for c in candidates] + [
                               "--- Winner(s) ---",
                               f"Winner: {', '.join(winners)}",
                               END
                           ]
        raw_result = CRLF.join(result_lines)

    # 向所有客户端广播加密结果
    with lock:
        for conn, shift in client_connections[:]:
            try:
                # 加密结果并发送
                encrypted_result = caesar_encrypt(add_checksum(raw_result), shift)
                conn.sendall(encrypted_result.encode("utf-8"))
                print(f"[INFO] 已向客户端 {conn.getpeername()} 发送结果")
            except Exception as e:
                print(f"[ERROR] 广播失败：{e}")
                client_connections.remove((conn, shift))


def wait_for_end():
    """等待用户按回车结束投票（独立线程）"""
    global voting_ended
    print("\n=== 服务器提示 ===")
    print("请在所有客户端投票完成后，按回车键结束投票并广播结果")
    input()  # 阻塞等待回车

    with lock:
        voting_ended = True
        print("\n[INFO] 投票已结束，开始计算结果...")

    broadcast_results()


def handle_client(conn, addr):
    """处理单个客户端的完整流程：认证→投票→等待结果"""
    server_private = generate_private_key()
    server_public = generate_public_key(server_private)
    shared_shift = None

    try:
        print(f"\n[INFO] 新客户端连接：{addr}")

        # 1. 身份认证（DH密钥交换+挑战响应）
        # 1.1 接收客户端公钥
        client_public = int(conn.recv(1024).decode().strip())
        conn.sendall(ACK.encode())
        # 1.2 发送服务器公钥
        conn.sendall(str(server_public).encode())
        if conn.recv(1024).decode().strip() != ACK:
            raise Exception("客户端未确认公钥")
        # 1.3 生成共享密钥
        shared_shift = generate_shared_secret(client_public, server_private)
        print(f"[INFO] 与 {addr} 的共享密钥（偏移量）：{shared_shift}")
        # 1.4 挑战响应验证
        challenge = f"AUTH_{random.randint(1000, 9999)}"
        conn.sendall(caesar_encrypt(challenge, shared_shift).encode())
        response = conn.recv(1024).decode().strip()
        if response != challenge:
            raise Exception("身份认证失败（共享密钥不匹配）")
        conn.sendall(ACK.encode())
        print(f"[INFO] {addr} 身份认证成功")

        # 2. 发送候选人列表（加密）
        with lock:
            if voting_ended:
                msg = f"ERROR: Voting has ended{CRLF}{END}"
                conn.sendall(caesar_encrypt(add_checksum(msg), shared_shift).encode())
                return
        msg_lines = ["OPTIONS"] + [f"Candidate: {c}" for c in candidates] + [END]
        raw_msg = CRLF.join(msg_lines)
        conn.sendall(caesar_encrypt(add_checksum(raw_msg), shared_shift).encode())
        if conn.recv(1024).decode().strip() != ACK:
            raise Exception("客户端未确认候选人列表")

        # 3. 接收选票（解密+校验）
        encrypted_vote = conn.recv(4096).decode()
        decrypted_vote = caesar_decrypt(encrypted_vote, shared_shift)
        valid, raw_vote = verify_checksum(decrypted_vote)
        if not valid:
            conn.sendall(NACK.encode())
            raise Exception("选票校验失败（可能被篡改）")
        # 解析选票
        chosen = raw_vote.replace(f"{CRLF}{END}", "").split(":", 1)[1].strip()
        if chosen not in candidates:
            conn.sendall(NACK.encode())
            raise Exception(f"无效候选人：{chosen}")
        # 记录选票
        with lock:
            votes[chosen] += 1
            client_connections.append((conn, shared_shift))  # 存储连接和共享密钥
        conn.sendall(ACK.encode())
        print(f"[INFO] {addr} 投票成功：{chosen}，当前票数：{dict(votes)}")

        # 4. 等待投票结束
        while True:
            with lock:
                if voting_ended:
                    break
            threading.Event().wait(0.5)  # 降低CPU占用

    except Exception as e:
        print(f"[ERROR] {addr} 处理失败：{e}")
    finally:
        conn.close()
        print(f"[INFO] {addr} 连接已关闭")


def start_server():
    """启动服务器主程序"""
    # 先启动“等待结束”线程（确保能捕获回车）
    end_thread = threading.Thread(target=wait_for_end, daemon=True)
    end_thread.start()

    # 启动服务器监听
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(16)
        print(f"[INFO] 服务器已启动，监听 {HOST}:{PORT}")
        print(f"[INFO] 候选人列表：{candidates}")

        try:
            while True:
                conn, addr = sock.accept()
                # 为每个客户端启动独立线程
                client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[INFO] 服务器手动关闭")


if __name__ == "__main__":
    start_server()
