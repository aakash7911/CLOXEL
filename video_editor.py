import os
from moviepy.editor import VideoFileClip, AudioFileClip, concatenate_videoclips, TextClip, CompositeVideoClip
from PIL import Image, ImageDraw, ImageFont

# Pillow 10+ fix
if not hasattr(Image, 'ANTIALIAS'):
    Image.ANTIALIAS = Image.LANCZOS

FONT_PATH = "./fonts/UTM Kabel KT.ttf"

def create_text_frame(text, size, font_path):
    # Ek transparent image banate hain text ke liye
    img = Image.new('RGBA', size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Font size setup
    try:
        font = ImageFont.truetype(font_path, 70)
    except:
        font = ImageFont.load_default()

    # Text wrapping (taki screen se bahar na jaye)
    import textwrap
    lines = textwrap.wrap(text, width=25)
    
    y_text = size[1] / 2 - (len(lines) * 40)
    for line in lines:
        # Text center mein align karne ke liye
        bbox = draw.textbbox((0, 0), line, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        
        # Black background box for readability (MoneyPrinter style)
        draw.rectangle([((size[0]-w)/2-10, y_text-5), ((size[0]+w)/2+10, y_text+h+5)], fill=(0,0,0,150))
        draw.text(((size[0]-w)/2, y_text), line, font=font, fill="white")
        y_text += h + 20
        
    return img

def merge_and_export(scene_list, output_name):
    print("\n🛠️ Editor: Pillow Text Overlay apply ho raha hai...")
    final_clips = []
    target_size = (1080, 1920)

    for scene in scene_list:
        v_clip = VideoFileClip(scene['video']).resize(height=target_size[1])
        if v_clip.w > target_size[0]:
            v_clip = v_clip.crop(x_center=v_clip.w/2, width=target_size[0])
        
        a_clip = AudioFileClip(scene['audio'])
        v_clip = v_clip.set_duration(a_clip.duration).set_audio(a_clip)

        # TEXT OVERLAY (Bina FFmpeg drawtext ke)
        txt_img = create_text_frame(scene['text'], target_size, FONT_PATH)
        import numpy as np
        # PIL Image ko MoviePy clip mein badalna
        from moviepy.video.VideoClip import ImageClip
        txt_clip = ImageClip(np.array(txt_img)).set_duration(a_clip.duration).set_position('center')
        
        # Video aur Text ko merge karo
        composite = CompositeVideoClip([v_clip, txt_clip])
        final_clips.append(composite)

    if final_clips:
        final_video = concatenate_videoclips(final_clips, method="compose")
        # Final export
        final_video.write_videofile(output_name, codec="libx264", audio_codec="aac", fps=24)
        print(f"\n✅ SUCCESS! Video ready: {output_name}")
        return output_name