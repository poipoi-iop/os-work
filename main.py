import os

from zhipuai import ZhipuAI
client = ZhipuAI(api_key='65b78e3989ee1f7e1db8a810befe3660.6GuJo1Sqn4P7OfY9')

file = open("./content.txt", 'r')
content = file.read()

response = client.chat.completions.create(
    model="glm-4-0520",
    messages=[
        {"role": "system", "content": f"你是一个精通 QEMU 和 libguestfs 的 Linux 开发者，你的任务是为我提供清晰的解决方案"},
        {"role": "user", "content": f"我在 OpenEuler 22.03 LTS-SP4 上调用命令 'virt-sysprep --root-password password:Liu20021231 -a EulixOS-3.0.qcow2'"
                                    f" 修改 QCOW2 镜像的 root 密码时有如下报错：'''{content}'''，请帮我分析错误原因，并给出一份详细的解决方案。其中 libguestfs 版本为 1.40.2"},
    ]
)

output = open("./output.txt", 'w')
output.write(response.choices[0].message.content)
# print(response.choices[0].message.content)
