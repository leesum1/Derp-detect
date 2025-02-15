import argparse
import csv
import json
import pandas as pd
import requests
import subprocess
import time
from tqdm import tqdm


def gen_acl_region_json(region_id, region_code, region_name, nodes):
    """
    根据 region ID、region code、region name 和节点列表生成 region 配置 JSON。

    参数:
    - region_id (int): region 的 ID
    - region_code (str): region 的代码标识
    - region_name (str): region 的名称
    - nodes (list): 包含所有节点的列表，每个节点是一个字典，格式如下:
        {
            "ip": "节点的IPv4地址",
            "port": "节点的DERP端口",
        }
    """

    # 构造所有节点信息
    node_list = []
    for idx, node in enumerate(nodes):
        node_list.append(
            {
                "Name": f"{region_id}-{idx}",
                "RegionID": region_id,
                "IPv4": node["ip"],
                "DERPPort": node["port"],
                "InsecureForTests": True,  # 可以根据需求调整
            }
        )

    region_config = {}

    region_config[f"{region_id}"] = {
        "RegionID": region_id,
        "RegionCode": region_code,
        "RegionName": region_name,
        "Nodes": node_list,
    }

    # # 字典转换为 JSON
    # region_config = json.dumps(region_config)

    return region_config


def generate_acl_config_json_from_regins(regions_list):

    regions = {}
    for region in regions_list:
        # 获取 region_id
        region_id = list(region.keys())[0]
        region_info = region[region_id]
        regions[region_id] = region_info

    # 构造最终的配置 JSON
    config = {
        "derpMap": {
            "OmitDefaultRegions": True,
            "Regions": regions,
        },
        "acls": [
            {
                "action": "accept",
                "src": [
                    "*",
                ],
                "dst": [
                    "*:*",
                ],
            },
        ],
        "ssh": [
            {
                "action": "check",
                "src": [
                    "autogroup:member",
                ],
                "dst": [
                    "autogroup:self",
                ],
                "users": [
                    "autogroup:nonroot",
                    "root",
                ],
            },
        ],
    }

    return config


def generate_acl_config_json_sigle(ipv4, derp_port):
    # 返回的 json 格式
    config = {
        "derpMap": {
            "OmitDefaultRegions": True,
            "Regions": {
                "910": {
                    "RegionID": 910,
                    "RegionCode": "test1",
                    "RegionName": "test1",
                    "Nodes": [
                        {
                            "Name": "test1",
                            "RegionID": 910,
                            "IPv4": ipv4,
                            "DERPPort": derp_port,
                            "InsecureForTests": True,
                        },
                    ],
                },
            },
        },
        "acls": [
            {
                "action": "accept",
                "src": [
                    "*",
                ],
                "dst": [
                    "*:*",
                ],
            },
        ],
        "ssh": [
            {
                "action": "check",
                "src": [
                    "autogroup:member",
                ],
                "dst": [
                    "autogroup:self",
                ],
                "users": [
                    "autogroup:nonroot",
                    "root",
                ],
            },
        ],
    }

    return config


def modify_acl_config_json(config_json, usrname, tskey):

    headers = {"Authorization": f"Bearer {tskey}"}

    url = f"https://api.tailscale.com/api/v2/tailnet/{usrname}/acl"
    try:
        response = requests.post(url, json=config_json, headers=headers)
        # print(response.text)
        # 检查请求是否成功
        if response.status_code != 200:
            print(f"Failed to modify acl config: {response.text}")
            return False
        else:
            return True
    except Exception as e:
        print(f"Exception occurred: {e}")
        return False


def tailscale_ping(host):
    process = subprocess.Popen(
        [
            "tailscale",
            "ping",
            host,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    start_time = time.time()
    while True:
        output = process.stdout.readline().decode("utf-8")
        print(output)
        if output == "" and process.poll() is not None:
            return False
        if output:
            if "pong from" in output:
                process.terminate()  # 手动中断程序
                return True
        if time.time() - start_time > 5:  # 设置超时时间为 5 秒
            process.terminate()  # 手动中断程序
            return False


def tailscale_iperf3(host, time, port=5201):
    try:
        result = subprocess.run(
            [
                "iperf3",
                "-c",
                host,
                "-t",
                str(time),
                "-p",
                str(port),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        output = result.stdout.decode("utf-8")
        print(output)
        lines = output.split("\n")
        for line in reversed(lines):
            if "receiver" in line:
                parts = line.split()

                # 速度
                bitrate = parts[-3]

                # 单位
                unit = parts[-2]
                if unit == "Mbits/sec":
                    return bitrate

                return "0"
        return "0"
    except subprocess.TimeoutExpired:
        return "0"


# def main():
#     print("Hello from derp-detect!")
#     final_result = []
#     target_host = "100.76.194.26"
#     iperf3_port = 25201
#     with open("ip_port.csv", mode="r", newline="", encoding="utf-8") as file:
#         reader = csv.DictReader(file)
#         ip_port = [(row["ip"], row["port"]) for row in reader]

#         for ip, port in tqdm(ip_port):

#             # 如果 port 为空，默认为 443
#             if port == "":
#                 port = 443

#             # 1. 使用 ip 和 port 生成 acl 配置文件
#             config_json = generate_acl_config_json_sigle(ip, int(port))
#             # 2. 修改 acl 配置文件
#             modify_ret = modify_acl_config_json(config_json)

#             if modify_ret == False:
#                 print(f"Failed to modify acl config for {ip}:{port}")
#                 continue
#             print(f"Successfully modified acl config for {ip}:{port}")
#             # sleep 5s
#             time.sleep(10)

#             # 3. tailscale_ping 测试
#             ping_ret = tailscale_ping(target_host)

#             if ping_ret == False:
#                 print(f"Failed to ping {ip}")
#                 continue

#             print(f"Successfully pinged {ip}")

#             # 4. tailscale_iperf3 测试
#             iperf3_ret = tailscale_iperf3(target_host, 5, iperf3_port)
#             # 将结果保存
#             print(f"iperf3 result for {ip}:{port}: {iperf3_ret}\n")
#             final_result.append((ip, port, "success", iperf3_ret))

#     # 将结果输出为 csv 文件
#     with open("final_result.csv", mode="w", newline="", encoding="utf-8") as file:
#         writer = csv.writer(file)
#         writer.writerow(["ip", "port", "status", "iperf3_result"])
#         for item in final_result:
#             writer.writerow(item)


def tailscale_derp_test(ori_csv, final_csv, usename, tskey, iperf3_host, iperf3_port):
    """用来测试 derp 的连通性以及性能

    Args:
        ori_csv (_type_): 待测试的 csv 文件
        final_csv (_type_): 测试结果的 csv 文件
        tskey (_type_): tailscale 的 api key
        iperf3_host (_type_): iperf3 服务器的 ip
        iperf3_port (_type_): iperf3 服务器的端口
    """
    final_result = []
    with open(ori_csv, mode="r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        ip_port = [(row["ip"], row["port"]) for row in reader]

        for ip, port in tqdm(ip_port):

            # 如果 port 为空，默认为 443
            if port == "":
                port = 443

            # 1. 使用 ip 和 port 生成 acl 配置文件
            config_json = generate_acl_config_json_sigle(ip, int(port))
            # 2. 修改 acl 配置文件
            modify_ret = modify_acl_config_json(config_json, usename, tskey)

            if modify_ret == False:
                print(f"Failed to modify acl config for {ip}:{port}")
                continue
            print(f"Successfully modified acl config for {ip}:{port}")
            # sleep 5s
            time.sleep(10)

            # 3. tailscale_ping 测试
            ping_ret = tailscale_ping(iperf3_host)

            if ping_ret == False:
                print(f"Failed to ping {ip}")
                continue

            print(f"Successfully pinged {ip}")

            # 4. tailscale_iperf3 测试
            iperf3_ret = tailscale_iperf3(iperf3_host, 5, iperf3_port)
            # 将结果保存
            print(f"iperf3 result for {ip}:{port}: {iperf3_ret}\n")
            final_result.append((ip, port, "success", iperf3_ret))

    # 将结果输出为 csv 文件
    with open(final_csv, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["ip", "port", "status", "iperf3_result"])
        for item in final_result:
            writer.writerow(item)


def main():
    parser = argparse.ArgumentParser(
        description="Test DERP connectivity and performance."
    )

    parser.add_argument(
        "--ori_csv",
        type=str,
        required=True,
        help="Path to the input CSV file containing IP and port information.",
    )
    parser.add_argument(
        "--final_csv",
        type=str,
        required=True,
        help="Path to the output CSV file to store the test results.",
    )
    parser.add_argument("--user", type=str, required=True, help="Tailscale user.")
    parser.add_argument("--tskey", type=str, required=True, help="Tailscale API key.")
    parser.add_argument(
        "--iperf3_host",
        type=str,
        required=True,
        help="IP address of the iperf3 server.",
    )
    parser.add_argument(
        "--iperf3_port", type=int, required=True, help="Port of the iperf3 server."
    )

    args = parser.parse_args()

    tailscale_derp_test(
        ori_csv=args.ori_csv,
        final_csv=args.final_csv,
        usename=args.user,
        tskey=args.tskey,
        iperf3_host=args.iperf3_host,
        iperf3_port=args.iperf3_port,
    )


def change_acl_config_json_final():
    # 读取 csv 文件
    df = pd.read_csv("data/final_result_with_province.csv")

    # 按照 province 进行分组
    region_id_start = 911
    regions_list = []
    df_grouped = df.groupby("province")
    for idx, (province, group) in enumerate(df_grouped):
        # 只保留 iperf3_result > 1.5 且 < 100 的数据
        group = group[(group["iperf3_result"] > 1.5) & (group["iperf3_result"] < 100)]
        if group.empty:
            continue
        # 按照 iperf3_result 排序
        group = group.sort_values(by="iperf3_result", ascending=False)

        cur_region_config = gen_acl_region_json(
            region_id_start + idx,
            f"{province}-{region_id_start + idx}",
            province,
            group[["ip", "port"]].to_dict("records"),
        )
        regions_list.append(cur_region_config)

    # 生成 ACL 配置 JSON
    config_json = generate_acl_config_json_from_regins(regions_list)
    modify_ret = modify_acl_config_json(config_json)
    print(f"modify_ret: {modify_ret}")


if __name__ == "__main__":
    main()
