import os
from PIL import Image, ImageDraw

def main():
    ev_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 1. Generate clean_evidence.jpg
    img_clean = Image.new('RGB', (400, 200), color=(255, 255, 255))
    d = ImageDraw.Draw(img_clean)
    d.text((20, 20), "SYSTEM CONFIGURATION v1.0", fill=(0, 0, 0))
    d.text((20, 60), "DATABASE_PORT = 5432", fill=(0, 0, 0))
    d.text((20, 100), "DEBUG = False", fill=(0, 0, 0))
    d.text((20, 140), "ALLOWED_HOSTS = ['*']", fill=(0, 0, 0))
    
    clean_path = os.path.join(ev_dir, 'clean_evidence.jpg')
    img_clean.save(clean_path, 'JPEG', quality=95)
    print(f"Generated clean evidence: {clean_path}")
    
    # 2. Generate tampered_evidence.jpg with ELA compression delta
    img_tampered = Image.open(clean_path).convert('RGB')
    dt = ImageDraw.Draw(img_tampered)
    dt.rectangle([90, 95, 170, 120], fill=(255, 255, 255))
    dt.text((90, 100), "True", fill=(200, 0, 0))
    
    tampered_path = os.path.join(ev_dir, 'tampered_evidence.jpg')
    img_tampered.save(tampered_path, 'JPEG', quality=85)
    print(f"Generated tampered evidence: {tampered_path}")

if __name__ == "__main__":
    main()
