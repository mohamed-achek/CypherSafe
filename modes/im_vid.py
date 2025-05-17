from PIL import Image
from io import BytesIO
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import json
import cv2
import numpy as np
import mediapipe as mp

def partial_encrypt_image(image_bytes, regions, key=None):
    """
    Encrypt user-defined rectangular regions on the image using AES.
    Returns a tuple: (protected_image_bytes, encrypted_regions_json)
    """
    image = Image.open(BytesIO(image_bytes)).convert("RGB")
    encrypted_regions = []
    for idx, (x, y, w, h) in enumerate(regions):
        region = image.crop((x, y, x + w, y + h))
        region_bytes_io = BytesIO()
        region.save(region_bytes_io, format="PNG")
        region_bytes = region_bytes_io.getvalue()
        if key:
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = iv + encryptor.update(region_bytes) + encryptor.finalize()
            encrypted_b64 = b64encode(encrypted_data).decode()
        else:
            encrypted_b64 = b64encode(region_bytes).decode()
        # Overwrite region with black box for visual feedback
        black = Image.new("RGB", (w, h), (0, 0, 0))
        image.paste(black, (x, y))
        encrypted_regions.append({
            "x": x, "y": y, "w": w, "h": h, "data": encrypted_b64
        })
    output = BytesIO()
    image.save(output, format="PNG")
    encrypted_regions_json = json.dumps(encrypted_regions)
    return output.getvalue(), encrypted_regions_json

def partial_decrypt_image(image_bytes, encrypted_regions_json, key):
    """
    Decrypt and restore the encrypted regions in the image using AES.
    """
    image = Image.open(BytesIO(image_bytes)).convert("RGB")
    encrypted_regions = json.loads(encrypted_regions_json)
    for region in encrypted_regions:
        x, y, w, h = region["x"], region["y"], region["w"], region["h"]
        encrypted_data = b64decode(region["data"])
        iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        region_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        region_img = Image.open(BytesIO(region_bytes)).convert("RGB")
        image.paste(region_img, (x, y))
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()

def encrypt_video_faces(
    video_bytes, key, iv, haar_cascade_path=None  # kept for compatibility, not used
):
    """
    Encrypt faces in video frames using AES and MediaPipe. Returns:
    - encrypted_video_bytes
    - metadata_json (with encrypted ROIs, positions, frame numbers)
    """
    import tempfile, os, json
    temp_in = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
    temp_in.write(video_bytes)
    temp_in.close()
    cap = cv2.VideoCapture(temp_in.name)
    if not cap.isOpened():
        raise RuntimeError("Failed to open video file for encryption.")
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    fps = cap.get(cv2.CAP_PROP_FPS)
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    temp_out = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
    out = cv2.VideoWriter(temp_out.name, fourcc, fps, (w, h))
    mp_face_detection = mp.solutions.face_detection
    frame_idx = 0
    metadata = []
    with mp_face_detection.FaceDetection(model_selection=0, min_detection_confidence=0.5) as face_detection:
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            results = face_detection.process(rgb_frame)
            frame_regions = []
            if results.detections:
                for detection in results.detections:
                    bboxC = detection.location_data.relative_bounding_box
                    x = int(bboxC.xmin * w)
                    y = int(bboxC.ymin * h)
                    fw = int(bboxC.width * w)
                    fh = int(bboxC.height * h)
                    # Clamp coordinates to frame
                    x = max(0, x)
                    y = max(0, y)
                    fw = min(fw, w - x)
                    fh = min(fh, h - y)
                    if fw <= 0 or fh <= 0:
                        continue
                    roi = frame[y : y + fh, x : x + fw]
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                    encryptor = cipher.encryptor()
                    roi_bytes = roi.tobytes()
                    pad_len = 16 - (len(roi_bytes) % 16)
                    roi_bytes_padded = roi_bytes + bytes([pad_len] * pad_len)
                    encrypted = encryptor.update(roi_bytes_padded) + encryptor.finalize()
                    frame_regions.append(
                        {
                            "frame": frame_idx,
                            "x": int(x),
                            "y": int(y),
                            "w": int(fw),
                            "h": int(fh),
                            "data": b64encode(encrypted).decode(),
                        }
                    )
                    frame[y : y + fh, x : x + fw] = 0
            metadata.extend(frame_regions)
            out.write(frame)
            frame_idx += 1
    cap.release()
    out.release()
    # Ensure files are closed before deleting
    encrypted_video_bytes = None
    with open(temp_out.name, "rb") as f:
        encrypted_video_bytes = f.read()
    try:
        os.remove(temp_in.name)
    except Exception:
        pass
    try:
        os.remove(temp_out.name)
    except Exception:
        pass
    metadata_json = json.dumps(metadata)
    return encrypted_video_bytes, metadata_json

def decrypt_video_faces(
    video_bytes, key, iv, metadata_json, frame_shape, dtype=np.uint8
):
    """
    Decrypt faces in video frames using AES and metadata.
    Returns decrypted video bytes.
    """
    import tempfile, os, json
    temp_in = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
    temp_in.write(video_bytes)
    temp_in.close()
    cap = cv2.VideoCapture(temp_in.name)
    if not cap.isOpened():
        raise RuntimeError("Failed to open video file for decryption.")
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    fps = cap.get(cv2.CAP_PROP_FPS)
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    temp_out = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
    out = cv2.VideoWriter(temp_out.name, fourcc, fps, (w, h))
    metadata = json.loads(metadata_json)
    from collections import defaultdict
    frame_regions = defaultdict(list)
    for region in metadata:
        frame_regions[region["frame"]].append(region)
    frame_idx = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        regions = frame_regions.get(frame_idx, [])
        for region in regions:
            x, y, fw, fh = region["x"], region["y"], region["w"], region["h"]
            encrypted = b64decode(region["data"])
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            roi_bytes_padded = decryptor.update(encrypted) + decryptor.finalize()
            pad_len = roi_bytes_padded[-1]
            roi_bytes = roi_bytes_padded[:-pad_len]
            roi = np.frombuffer(roi_bytes, dtype=dtype).reshape((fh, fw, 3))
            frame[y : y + fh, x : x + fw] = roi
        out.write(frame)
        frame_idx += 1
    cap.release()
    out.release()
    decrypted_video_bytes = None
    with open(temp_out.name, "rb") as f:
        decrypted_video_bytes = f.read()
    try:
        os.remove(temp_in.name)
    except Exception:
        pass
    try:
        os.remove(temp_out.name)
    except Exception:
        pass
    return decrypted_video_bytes
