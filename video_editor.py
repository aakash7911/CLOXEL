import os
import numpy as np
import textwrap
from moviepy.editor import VideoFileClip, AudioFileClip, concatenate_videoclips, CompositeVideoClip
from moviepy.video.VideoClip import ImageClip
from PIL import Image, ImageDraw, ImageFont

# Pillow 10+ fix
if not hasattr(Image, 'ANTIALIAS'):
    Image.ANTIALIAS = Image.LANCZOS

FONT_PATH = "./fonts/UTM Kabel KT.ttf"

def create_text_frame(text, size, font_path):
    img = Image.new('RGBA', size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    try:
        font = ImageFont.truetype(font_path, 60) # Font thoda chota kiya RAM bachane ko
    except:
        font = ImageFont.load_default()

    lines = textwrap.wrap(text, width=22)
    y_text = size[1] / 2 - (len(lines) * 40)
    
    for line in lines:
        bbox = draw.textbbox((0, 0), line, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        
        # MoneyPrinter Style Background
        draw.rectangle([((size[0]-w)/2-15, y_text-5), ((size[0]+w)/2+15, y_text+h+5)], fill=(0,0,0,160))
        draw.text(((size[0]-w)/2, y_text), line, font=font, fill="yellow") # Viral Yellow Color
        y_text += h + 25
        
    return img

def merge_and_export(scene_list, output_name):
    print("\n🛠️ Editor: RAM Optimized Rendering shuru ho rahi hai...")
    final_clips = []
    # Resolution thoda kam kiya (720p) taki Render crash na ho
    target_size = (720, 1280) 

    for scene in scene_list:
        # Memory bachane ke liye resize pehle hi kar rahe hain
        v_clip = VideoFileClip(scene['video']).resize(width=target_size[0])
        
        # Audio attach
        a_clip = AudioFileClip(scene['audio'])
        v_clip = v_clip.set_duration(a_clip.duration).set_audio(a_clip)

        # Text Overlay
        txt_img = create_text_frame(scene['text'], target_size, FONT_PATH)
        txt_clip = ImageClip(np.array(txt_img)).set_duration(a_clip.duration).set_position('center')
        
        composite = CompositeVideoClip([v_clip, txt_clip], size=target_size)
        final_clips.append(composite)

    if final_clips:
        final_video = concatenate_videoclips(final_clips, method="compose")
        
        # SABSE ZAROORI SETTINGS: RAM bachane ke liye
        final_video.write_videofile(
            output_name, 
            codec="libx264", 
            audio_codec="aac", 
            fps=12,              # FPS 24 se 12 kiya (Bohot RAM bachegi)
            threads=1,           # Sirf 1 thread taki Render kill na kare
            preset="ultrafast",  # Fast process taki memory build-up na ho
            logger=None          # Extra logs band kiye
        )
        
        # Memory saaf karne ke liye clips close karein
        for clip in final_clips: clip.close()
        final_video.close()
        
        print(f"\n✅ SUCCESS! Memory-Safe Video ready: {output_name}")
        return output_name
