from inspect import CO_NESTED
from adkg.broadcast.reliablebroadcast import reliablebroadcast
from adkg.acss import Hbacss0SingleShare
from adkg.polynomial import polynomials_over
from adkg.share_recovery import interpolate_g1_at_x
from pypairing import G1, ZR
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib
import time
import logging
import socket
import threading
from adkg.utils.serilization import serialize_g, deserialize_g, serialize_f, deserialize_f
from adkg.utils.bitmap import Bitmap

class ADKGMsgType:
    ACSS = "A"
    RBC = "R"
    ABA = "B"
    KEY = "K"
    
class CP:
    def __init__(self, g, h, field=ZR):
        self.g  = g
        self.h = h

    #零知识证明构建(哈希)
    def dleq_derive_chal(self, x, y, a1, a2):
        commit = str(x)+str(y)+str(a1)+str(a2)
        try:
            commit = commit.encode()
        except AttributeError:
            pass 
        # TODO: Convert the hash output to a field element.
        hs =  hashlib.sha256(commit).digest() 
        return ZR.hash(hs)
    # 验证离散对数等式证明
    def dleq_verify(self, x, y, chal, res):
        a1 = (x**chal)*(self.g**res)
        a2 = (y**chal)*(self.h**res)
        eLocal = self.dleq_derive_chal(x, a1, y, a2)
        if eLocal == chal:
            return True
        return False


    # 生成离散对数等式证明。
    def dleq_prove(self, alpha, x, y):
        w = ZR.random()
        a1 = self.g**w
        a2 = self.h**w
        e = self.dleq_derive_chal(x, a1, y, a2)
        return  e, w - e*alpha # return (challenge, response)


class ADKG:
    def __init__(self, public_keys, private_key, g, h, n, t, my_id, send, recv, pc, field=ZR):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.my_id = (n, t, my_id)
        self.send, self.recv, self.pc, self.field = (send, recv, pc, field)
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()


        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )


    # kill掉所有在ADKG实例中启动的异步任务    
    def kill(self):
        self.benchmark_logger.info("ADKG kill called")
        self.subscribe_recv_task.cancel()
        self.benchmark_logger.info("ADKG Recv task canceled called")
        for task in self.acss_tasks:
            task.cancel()
        self.benchmark_logger.info("ADKG ACSS tasks canceled")
        # TODO: To determine the order of kills, I think that might giving that error.
        # 1. 
        self.acss.kill()
        self.benchmark_logger.info("ADKG ACSS killed")
        self.acss_task.cancel()
        self.benchmark_logger.info("ADKG ACSS task killed")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    
    # ----------------------异步执行ACSS---------------------
    async def acss_step(self, outputs, value, acss_signal):
        #todo, need to modify send and recv
        # Need different send and recv instances for different component of the code.
        acsstag = ADKGMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = Hbacss0SingleShare(self.public_keys, self.private_key, self.g, self.n, self.t, self.my_id, acsssend, acssrecv, self.pc)
        self.acss_tasks = [None] * self.n
        # value =[ZR.rand()]
        logging.info(f"self.n: {(self.n)}")
        logging.info(f"self.my_id: {(self.my_id)}")
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, values=value))# 发送者
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, dealer_id=i))# 接收者
            logging.info(f"i: {(i)}")
        # 发送者和接收者的角色不同任务也不同
        while True:
                (dealer, _, share, commitments) = await self.acss.output_queue.get()
                # outputs： 字典，用于存储ACSS的输出。每个参与节点完成秘密分享后，其输出（包括份额和承诺）将存储在这个字典中。
                outputs[dealer] = [share, commitments]
                # if len(outputs) >= self.n - self.t:
                logging.info(f"len(outputs): {(len(outputs))}")
                
                if len(outputs) > self.t:
                    # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                    acss_signal.set()
                    # acss_signal：个异步事件标志，当ACSS步骤完成足够的份额时，该标志会被设置，以通知其他协议组件可以继续执行。

                if len(outputs) == self.n:
                    return    

    async def commonsubset(self, rbc_out, acss_outputs, acss_signal, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n
        # 处理RBC输出   
        async def _recv_rbc(j):
            # rbc_values[j] = await rbc_out[j]
            rbcl = await rbc_out[j].get()
            rbcb = Bitmap(self.n, rbcl)
            rbc_values[j] = []
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
                    
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1) # 向异步队列aba_in[j]中发送1
# --------------------------------------------------------------------------------            
            subset = True
            while True:
                acss_signal.clear()
                for k in rbc_values[j]:
                    if k not in acss_outputs.keys():
                        subset = False
                if subset:
                    coin_keys[j]((acss_outputs, rbc_values[j]))
                    return
                await acss_signal.wait()
                # 当调用 acss_signal.wait() 时，当前的异步任务会暂停，直到 acss_signal 事件被另一个任务触发（通常是通过调用 acss_signal.set() 方法）

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]
        # 接收 ABA 输出
        async def _recv_aba(j):
            aba_values[j] = await aba_out[j]()  # May block
            # print pid, j, 'ENTERING CRITICAL'
            # if sum(aba_values) >= self.n - self.t:
            if sum(aba_values) >= 1:
                # Provide 0 to all other aba
                for k in range(self.n):
                    if not aba_inputted[k]:
                        aba_inputted[k] = True
                        aba_in[k](0)
        # 并行处理所有 ABA 任务
        await asyncio.gather(*[asyncio.create_task(_recv_aba(j)) for j in range(self.n)])
        # assert sum(aba_values) >= self.n - self.t  # Must have at least N-f committed
        assert sum(aba_values) >= 1  # Must have at least N-f committedassert 是一个用于测试表达式的语句。如果表达式为真（True），程序继续执行；如果为假（False），程序会触发一个 AssertionError 异常。

        # Wait for the corresponding broadcasts
        # 等待 RBC 任务完成或取消
        for j in range(self.n):
            if aba_values[j]:
                await r_threads[j]
                assert rbc_values[j] is not None
            else:
                r_threads[j].cancel()
                rbc_values[j] = None
        # 一旦完成，设置 rbc_signal 以指示 RBC 步骤已完成。
        rbc_signal.set()

    async def agreement(self, key_proposal, acss_outputs, acss_signal):
        from adkg.broadcast.tylerba import tylerba
        # from adkg.broadcast.qrbc import qrbc
        from adkg.broadcast.optqrbc import optqrbc
        # asyncio.Queue() 是一个用于异步编程的队列类，创建了一个列表，包含n个队列
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_key_proposal):
            # 用于判断给定的键提议（_key_proposal）是否满足某些条件。
            # 将 _key_proposal 转换为位图格式，然后检查满足条件的节点数是否超过阈值 self.t
            kp = Bitmap(self.n, _key_proposal)
            kpl = []
            for ii in range(self.n):
                if kp.get_bit(ii):
                    kpl.append(ii)

            if len(kpl) <= self.t:
                return False
        # 如果超过，函数会等待 acss_signal 的信号，以确定是否所有必需的 acss_outputs 都已经收到。
        # 如果收到了所有必需的输出，函数返回 True，表示提议满足条件；否则，继续等待直到条件得到满足
            while True:
                subset = True
                for kk in kpl:
                    if kk not in acss_outputs.keys():
                        subset = False
                if subset:
                    acss_signal.clear()    
                    return True
                acss_signal.clear()
                await acss_signal.wait()

        async def _setup(j):
            
            # starting RBC
            rbctag =ADKGMsgType.RBC + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)
            # subscribe_recv函数的作用是创建一个机制来根据消息的标签（tag）分割接收（recv）通道。
            # 具体来说，它允许程序根据不同的消息类型或来源来处理接收到的消息，
            # 从而使程序能够更有效地管理和响应网络通信。在分布式系统或网络协议中，
            # 这种机制是非常有用的，因为它可以帮助确保正确的消息被发送到正确的处理程序。
            rbc_input = None
            if j == self.my_id: 
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)# 在riv位图中第k位将被设置为1
                rbc_input = bytes(riv.array)# 位图riv转换成字节数组（bytes）

            # rbc_outputs[j] = 
            asyncio.create_task(
                optqrbc(
                    rbctag,
                    self.my_id,
                    self.n,
                    self.t,
                    j,
                    predicate,
                    rbc_input,
                    rbc_outputs[j].put_nowait,
                    rbcsend,
                    rbcrecv,
                )
            )
            # 函数optqrbc是一个异步函数，用于实现一种优化的可靠广播协议（Optimized Quorum Reliable Broadcast）。

            # asyncio.create_task() 函数用于创建一个新的异步任务。这个函数接收一个异步函数调用作为参数，并返回一个 Task 对象。
            abatag = ADKGMsgType.ABA + str(j) # (B, msg)
            # abatag = j # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in range(self.n):
                    abasend(i, o)
                
            aba_task = asyncio.create_task(
                tylerba(
                    abatag,
                    self.my_id,
                    self.n,
                    self.t,
                    coin_keys[j].get,
                    aba_inputs[j].get,
                    aba_outputs[j].put_nowait,
                    bcast,
                    abarecv,
                )
            )
            return aba_task
            # 函数 tylerba 是异步二进制协议（Asynchronous Binary Agreement, ABA）的实现。
        work_tasks = await asyncio.gather(*[_setup(j) for j in range(self.n)])
        rbc_signal = asyncio.Event()
        rbc_values = [None for i in range(self.n)]

        return (
            self.commonsubset(
                rbc_outputs,
                acss_outputs,
                acss_signal,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.derive_key(
                acss_outputs,
                acss_signal,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    async def derive_key(self, acss_outputs, acss_signal, rbc_values, rbc_signal):
        # Waiting for the ABA to terminate
        await rbc_signal.wait()
        rbc_signal.clear()

        mks = set() # master key set
        # rbc_values[i]=T[i]：
        for ks in  rbc_values:
            if ks is not None:
                mks = mks.union(set(list(ks)))# 合并mks和ks两个集合

        for k in mks:
            if k not in acss_outputs:
                await acss_signal.wait()# 确保收到的所有的rbc_values中的节点发布的acss信息(s,v)
                acss_signal.clear()

        
        secret = 0
        # G1 代表一个特定类型的椭圆曲线群
        # G1.identity() 是一个调用，它返回 G1 群的恒等元。
        # 在椭圆曲线群中，恒等元是一个特殊的元素，它类似于数学中的零。
        # 在群的运算下，任何群元素与恒等元的运算结果都是该元素本身。
        # 例如，在加法群中，恒等元是 0；在乘法群中，恒等元是 1。
        # coeffs = [G1.identity() for _ in range(self.t+1)]
        z_G=G1.identity()
        for k in mks:
            secret = secret + acss_outputs[k][0][0] #所有的s_{k,i}相加
            # Computing aggregated coeffients
            z_G=z_G*acss_outputs[k][1][0][0]
            # for i in range(self.t+1):
            #     coeffs[i] = coeffs[i]*acss_outputs[k][1][0][i]
            # logging.info(f"acss_outputs: {(acss_outputs[k][1][0])}")


        # x = self.g**secret
        # y = self.h**secret
        # cp = CP(self.g, self.h)
        # chal, res = cp.dleq_prove(secret, x, y)

        # keytag = ADKGMsgType.KEY
        # send, recv = self.get_send(keytag), self.subscribe_recv(keytag)

        # # print("Node " + str(self.my_id) + " starting key-derivation")
        # yb, chalb, resb = serialize_g(y), serialize_f(chal), serialize_f(res)
        # for i in range(self.n):
        #     send(i, (yb, chalb, resb))

        # pk_shares = []
        # while True:
        #     (sender, msg) = await recv()
        #     yb, chalb, resb = msg
        #     y, chal, res = deserialize_g(yb), deserialize_f(chalb), deserialize_f(resb)

        #     # polynomial evaluation, not optimized
        #     x = G1.identity()
        #     exp = ZR(1)
        #     for j in range(self.t+1):
        #         x *= coeffs[j]**exp
        #         exp *= (sender+1)
        
            
        #     if cp.dleq_verify(x, y, chal, res):
        #         pk_shares.append([sender+1, y])
        #         # print("Node " + str(self.my_id) + " received key shares from "+ str(sender))
        #     if len(pk_shares) > self.t:
        #         break
        # pk =  interpolate_g1_at_x(pk_shares, 0)# 这个函数用于在椭圆曲线上根据一组坐标点和一个特定的 x 值，
        # # 使用拉格朗日插值法计算出一个点。函数返回计算出的插值结果 out，这是椭圆曲线群 G1 上的一个点。
        # # pk：最终的公钥 
        
        zi_G = self.g**secret
        zi = secret
        # return (mks, secret , pk)
        return (mks, z_G, zi, zi_G)

    # TODO: This function given an index computes g^x
    def derive_x(self, acss_outputs, mks):
        xlist = []
        for i in range(self.n):
            xi = G1.identity()
            for ii in mks:
                # TODO: This is not the correct implementation.
                xi = xi*acss_outputs[ii][i]
            xlist.append(xi)
        return xlist

    async def run_adkg(self, start_time):
        acss_outputs = {}
        acss_signal = asyncio.Event()

        acss_start_time = time.time()
        value =[ZR.rand()]
        # G1.rand()随机生成点，ZR.rand()随机生成数
        logging.info("# 启动 ACSS 步骤，等待其完成")
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, value, acss_signal))
        # asyncio.Event对象。asyncio.Event是一个用于协调异步协程之间状态的同步原语。这个对象有两个主要状态：设置（set）和未设置（clear）。
        await acss_signal.wait()
        acss_signal.clear()
        # 事件回到未设置状态。在这种状态下，任何调用await event.wait()的协程都将等待，直到事件再次被设置。
        # 将acss_signal事件对象重置为未设置状态。这通常是为了准备下一次的事件等待，确保在此事件再次被设置之前，任何等待这个事件的协程都将暂停执行。
        acss_time = time.time() - acss_start_time
        logging.info(f"ACSS time: {(acss_time)}")
        
        key_proposal = list(acss_outputs.keys())

        logging.info("# 根据 ACSS 输出创建一个关于密钥提议的任务，并等待其完成")
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, acss_outputs, acss_signal))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        adkg_time = time.time()-start_time
        self.benchmark_logger.info("ADKG time2: %f", adkg_time)
        logging.info(f"ADKG time: {(adkg_time)}")
        await asyncio.gather(*work_tasks)
        # mks, sk, zi_G , pk = output # T zi 公钥
        mks,z_G, zi, zi_G = output
        logging.info(f"T(mks): {(mks)}")
        logging.info(f"z_G: {(z_G)}")
        logging.info(f"zi*G: {(zi_G)}")
        logging.info(f"zi: {(zi)}")
        
        try:
            #容器的ip地址
            server_ip = '172.17.0.1'
            # 服务端口号
            server_port = 8889
            # 创建客户端Socket
            client_port = 58000 + self.my_id
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                # 绑定客户端端口
                client_socket.bind(('', client_port))
                # 连接服务端
                client_socket.connect((server_ip, server_port))
                print(f"[Node-{self.my_id}] 成功连接服务端 {server_ip}:{server_port}")

                # 发送数据
                message = f"{self.my_id}:{zi}:{zi_G}:{z_G}"
                client_socket.sendall(message.encode('utf-8'))
                print(f"[Node-{self.my_id}] 发送数据: {message}")

                # 接收响应（阻塞等待）
                response = client_socket.recv(1024)
                print(f"[Node-{self.my_id}] 服务端响应: {response.decode('utf-8')}")

        except Exception as e:
            print(f"[Node-{self.my_id}] 发生错误: {str(e)}")
        
        # print("self.g: ",self.g)
        # print("self.h: ",self.h)
        # print("self.g+self.g: ",self.g+self.g)
        # print("self.g*2: ",self.g*2)
        # print("self.g**2: ",self.g**2)
        # print("-------------------------------------")
        
        self.output_queue.put_nowait((value[0], mks, sk, pk))# 这个方法用于将一个元素(value[0], mks, sk, pk)立即放入队列中，而不等待。
        

