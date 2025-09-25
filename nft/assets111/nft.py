import os
import json
import random
from PIL import Image

# ==== 配置区 ====
original_image = "0.png"   # 原始图片路径
output_dir = "assets_new"          # 输出目录
num_copies = 5                     # 生成数量
collection_name = "unionkey"
symbol = "CNFT"
description_prefix = "unionkey #"

# ==== 创建目录 ====
images_dir = os.path.join(output_dir, "images")
metadata_dir = os.path.join(output_dir, "metadata")
os.makedirs(images_dir, exist_ok=True)
os.makedirs(metadata_dir, exist_ok=True)

# ==== 生成新图片和 metadata ====
for i in range(num_copies):
    # 打开原图
    img = Image.open(original_image).convert("RGBA")
    pixels = img.load()

    # 随机修改一个像素(微调，不影响肉眼)
    x = random.randint(0, img.width-1)
    y = random.randint(0, img.height-1)
    r, g, b, a = pixels[x, y]
    pixels[x, y] = ((r + 1) % 256, g, b, a)

    # 保存新图片
    new_image_name = f"{i}.png"
    img.save(os.path.join(images_dir, new_image_name))

    # 生成 metadata
    metadata = {
        "name": f"{collection_name} #{i+1}",
        "symbol": symbol,
        "description": f"{description_prefix}{i+1}",
        "seller_fee_basis_points": 0,
        "image": new_image_name,
        "attributes": [
            {"trait_type": "Background", "value": "Blue"},
            {"trait_type": "Mood", "value": "Happy"}
        ],
        "collection": {
            "name": collection_name,
            "family": collection_name
        },
        "properties": {
            "files": [
                {"uri": new_image_name, "type": "image/png"}
            ],
            "category": "image"
        }
    }

    metadata_filename = f"{i}.json"
    with open(os.path.join(metadata_dir, metadata_filename), "w") as f:
        json.dump(metadata, f, indent=2)

print(f"生成完成！请使用 Sugar 指向 {output_dir} 上传。")
