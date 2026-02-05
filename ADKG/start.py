import socket
import threading
from flask import Flask, jsonify
from flask_cors import CORS
import os
import subprocess
import datetime
import random
import time
from flask import request

app = Flask(__name__)
#允许跨域请求
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
ADKG_WORKDIR = os.path.join(BASE_DIR, "adkg")
FRONTEND_DIR = os.path.join(BASE_DIR, "access-control-front-end")

# 用于存储节点信息
info = {}
extra_nodes = {}
z_G_set = set()

@app.route('/api/zG', methods=['GET'])
def get_z_G():
    try:
        # 返回 z_G 集合的内容
        return jsonify({'z_G': list(z_G_set)})
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve z_G: {str(e)}'}), 500

@app.route('/api/log', methods=['GET'])
def get_log():
    try:
        # 从请求参数中获取 node_id
        node_id = request.args.get('node_id')
        
        if not node_id:
            return jsonify({'error': 'node_id parameter is required'}), 400
        
        print(f"Received request for node_id: {node_id}")
        
        # 如果 node_id 大于等于 10，直接返回空
        if int(node_id) >= 10:
            return jsonify({
                'node_id': node_id,
                'log_content': ''
            })
        
        # 构建日志文件路径
        log_file_path = os.path.join(LOG_DIR, f"logs-{node_id}.log")
        
        # 检查文件是否存在
        if not os.path.exists(log_file_path):
            return jsonify({'error': f'Log file for node {node_id} not found'}), 404
        
        # 读取日志文件内容
        with open(log_file_path, 'r', encoding='utf-8') as f:
            log_content = f.read()
        
        return jsonify({
            'node_id': node_id,
            'log_content': log_content
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to read log file: {str(e)}'}), 500

@app.route('/api/generate', methods=['GET'])
def generate_data():     
    # 启动两个线程分别运行 docker 和 adkg
    adkg_thread_a = threading.Thread(target=run_adkg_container)
    adkg_thread_b = threading.Thread(target=enter_adkg_container_and_run_script)

    #先启动docker，再在docker中运行脚本启动adkg
    adkg_thread_a.start()
    threading.Timer(1, adkg_thread_b.start).start()  # 1秒后启动线程b
    
    # 设置最大等待时间（比如30秒）
    max_wait_time = 30
    start_time = time.time()
    
    while len(info) < 10:
        if time.time() - start_time > max_wait_time:
            print(f"警告：等待超时，当前只收集到 {len(info)} 个节点")
            break
        time.sleep(2)  # 使用 time.sleep 替代错误的 Event.wait
    return jsonify({
        "status": "started",
        "nodes_collected": len(info)
    })
    
@app.route('/api/data', methods=['GET'])
def get_data():  
    # 返回收集到的所有节点信息  
    # 添加额外的54个节点 
    # 确保有node_id为0的节点作为pk参考
    if '0' in info:
        reference_pk = info['0'][1]  # 获取node_id为0的pk
            
        # 获取已有节点的sk列表（node_id 0-9）
        existing_sks = [info[str(i)][0] for i in range(10) if str(i) in info]
            
        if existing_sks:  # 确保有可用的sk
            for node_id in range(10, 64):
                # 随机选择一个已有的sk
                random_sk = random.choice(existing_sks)
                # 使用node_id为0的pk
                pk = reference_pk
                # 生成端口号
                random_port = 58000 + node_id
                addr = f"172.18.0.2:{random_port}"
                    
                # 添加到返回的JSON中
                extra_nodes[str(node_id)] = {
                    'name': f"docker-{node_id}",
                    'sk': random_sk,
                    'pk': pk,
                    'address': addr,
                    'cur_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
        
    # 合并原有节点和新增节点
    all_nodes = {
        node_id: {
            'name': "docker-" + node_id, 
            'sk': sk,
            'pk': pk,
            'address': addr,
            'cur_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        } for node_id, (sk, pk, addr) in info.items()
    }
    # 添加额外的54个节点
    all_nodes.update(extra_nodes)
        
    return jsonify({
        'nodes': all_nodes
})

def handle_client(client_socket, client_addr):
    try:
        data = client_socket.recv(1024)
        if data:
            print(f"接收数据: {data.decode('utf-8')}")
            data_str = data.decode('utf-8')
            node_id, sk, pk, z_G = data_str.split(':')
            # 将z_G添加到集合中（自动去重）
            z_G_set.add(z_G)
            addr = f"{client_addr[0]}:{client_addr[1]}"
            info[node_id] = [sk, pk, addr]
            client_socket.send(b"Server response: OK")
    except Exception as e:
        print(f"处理客户端时发生错误: {e}")
    finally:
        client_socket.close()
        print(f"[-] 客户端断开: {client_addr[0]}:{client_addr[1]}")

def run_server(host='0.0.0.0', port=8889):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[*] 服务端启动，监听 {host}:{port}")
    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            print(f"[+] 客户端连接: {client_addr[0]}:{client_addr[1]}")
            client_thread = threading.Thread(
                target = handle_client,
                args = (client_socket, client_addr)
            )
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[*] 服务端关闭")
    finally:
        server_socket.close()
        
def run_frontend():
    if not os.path.isdir(FRONTEND_DIR):
        print(f"未找到前端目录: {FRONTEND_DIR}")
        return
    os.chdir(FRONTEND_DIR)
    subprocess.run(['npm', 'run', 'dev'])
        
def run_adkg_container():
    os.chdir(ADKG_WORKDIR)
    subprocess.run(['sudo', '-S', 'docker', 'compose', 'run', '--rm', '-T', 'adkg', 'bash'], input='lsc20011130\n', text=True)

def enter_adkg_container_and_run_script():
    try:
        # 获取容器ID
        result = subprocess.run(['sudo', '-S', 'docker', 'ps', '-q', '--filter', 'ancestor=sm2_adkg-adkg-adkg'], capture_output=True, text=True, input='lsc20011130\n')
        container_id = result.stdout.strip()
        if container_id:
            cmd = [
                'sudo', '-S', 'docker', 'exec', '-i', container_id, '/bin/sh', 
                '-c', 'sh scripts/launch-tmuxlocal.sh apps/tutorial/adkg-tutorial.py conf/adkg/local'
            ]
            subprocess.run(cmd, input='lsc20011130\n', text=True)
        else:
            print("未找到运行中的 adkg 容器")
    except Exception as e:
        print(f"进入容器并运行脚本时发生错误: {e}")
        

if __name__ == '__main__':
    # 启动两个线程分别运行 Flask 和 socket 服务器
    flask_thread = threading.Thread(target=lambda: app.run(debug=False, host='0.0.0.0', port=5000))
    socket_thread = threading.Thread(target=run_server)
    
    flask_thread.start()
    socket_thread.start()

    #启动线程运行前端
    frontend_thread = threading.Thread(target=run_frontend)
    frontend_thread.start()
    
    



