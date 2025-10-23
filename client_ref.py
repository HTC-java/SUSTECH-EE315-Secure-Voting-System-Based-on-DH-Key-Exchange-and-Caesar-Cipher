import argparse
import socket
import time
import random  # 必须导入random模块

def generate_private_key():
    return random.randint(1, 100)

def generate_public_key(private_key, p=23, g=5):
    return (g ** private_key) % p

def generate_shared_secret(their_public_key, private_key, p=23):
    shared = (their_public_key ** private_key) % p
    return shared % 26

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

# -------------------------- 客户端配置 --------------------------
CRLF = "\r\n"
END = "END"
ACK = "ACK"
NACK = "NACK"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18080)
    args = ap.parse_args()

    # 生成客户端DH密钥
    client_private = generate_private_key()
    client_public = generate_public_key(client_private)
    shared_shift = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((args.host, args.port))
            print(f"[INFO] 已连接服务器：{args.host}:{args.port}")
        except Exception as e:
            print(f"[ERROR] 连接失败：{e}")
            return

        try:
            # 1. 身份认证
            # 1.1 发送客户端公钥
            sock.sendall(str(client_public).encode())
            if sock.recv(1024).decode().strip() != ACK:
                raise Exception("服务器未确认公钥")
            # 1.2 接收服务器公钥
            server_public = int(sock.recv(1024).decode().strip())
            sock.sendall(ACK.encode())
            # 1.3 生成共享密钥
            shared_shift = generate_shared_secret(server_public, client_private)
            print(f"[INFO] 共享密钥（偏移量）：{shared_shift}")
            # 1.4 响应挑战
            encrypted_challenge = sock.recv(1024).decode()
            challenge = caesar_decrypt(encrypted_challenge, shared_shift)
            sock.sendall(challenge.encode())
            if sock.recv(1024).decode().strip() != ACK:
                raise Exception("身份认证失败")
            print("[INFO] 身份认证成功")

            # 2. 接收候选人列表
            encrypted_options = sock.recv(4096).decode()
            decrypted_options = caesar_decrypt(encrypted_options, shared_shift)
            valid, raw_options = verify_checksum(decrypted_options)
            if not valid:
                raise Exception("候选人列表校验失败")
            sock.sendall(ACK.encode())
            # 解析候选人
            candidates = []
            for line in raw_options.splitlines():
                if line.startswith("Candidate:"):
                    candidates.append(line.split(":", 1)[1].strip())
            print("\n=== 候选人列表 ===")
            for i, c in enumerate(candidates, 1):
                print(f"[{i}] {c}")

            # 3. 提交选票
            while True:
                inp = input("\n请输入候选人编号或姓名：").strip()
                if inp.isdigit():
                    idx = int(inp) - 1
                    if 0 <= idx < len(candidates):
                        choice = candidates[idx]
                        break
                    print("无效编号，请重试")
                else:
                    if inp in candidates:
                        choice = inp
                        break
                    print("无效姓名，请重试")
            # 发送加密选票
            raw_vote = f"VOTE: {choice}{CRLF}{END}"
            encrypted_vote = caesar_encrypt(add_checksum(raw_vote), shared_shift)
            sock.sendall(encrypted_vote.encode())
            if sock.recv(1024).decode().strip() != ACK:
                raise Exception("选票提交失败")
            print(f"[INFO] 已提交选票：{choice}，等待投票结束...")

            # 4. 接收投票结果
            encrypted_result = sock.recv(4096).decode()
            decrypted_result = caesar_decrypt(encrypted_result, shared_shift)
            valid, raw_result = verify_checksum(decrypted_result)
            if not valid:
                raise Exception("结果校验失败（可能被篡改）")
            # 显示结果
            print("\n" + "="*30)
            print("         投票最终结果")
            print("="*30)
            for line in raw_result.splitlines():
                line = line.strip()
                if line and line not in ["VOTE_RESULTS", END]:
                    print(f"  {line}")
            print("="*30)

        except Exception as e:
            print(f"[ERROR] 操作失败：{e}")

if __name__ == "__main__":
    main()