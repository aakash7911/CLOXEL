import os
import random
import numpy as np
import textwrap
from moviepy.editor import VideoFileClip, AudioFileClip, concatenate_videoclips, CompositeVideoClip, ImageSequenceClip
from PIL import Image, ImageDraw, ImageFont

# Pillow 10+ fix
if not hasattr(Image, 'ANTIALIAS'):
    Image.ANTIALIAS = Image.LANCZOS

def create_animated_text(full_text, size, duration, font_path, highlight_color):
    """
    Ek specific segment ke liye animation banata hai
    """
    frames = []
    fps = 10
    total_frames = int(duration * fps)
    words = full_text.split()
    
    try:
        font = ImageFont.truetype(font_path, 75) 
    except:
        font = ImageFont.load_default()

    for i in range(total_frames):
        img = Image.new('RGBA', size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Current word highlight logic
        word_idx = int((i / total_frames) * len(words)) if words else 0
        
        wrapped_text = textwrap.fill(full_text, width=18)
        lines = wrapped_text.split('\n')
        
        total_h = len(lines) * 110
        y_text = (size[1] - total_h) / 1.5 
        
        current_word_count = 0
        for line in lines:
            line_words = line.split()
            line_width = draw.textbbox((0, 0), line, font=font)[2]
            current_x = (size[0] - line_width) / 2
            
            for word in line_words:
                color = highlight_color if current_word_count <= word_idx else "white" 
                draw.text((current_x+5, y_text+5), word, font=font, fill=(0,0,0,200))
                draw.text((current_x, y_text), word, font=font, fill=color)
                current_x += draw.textbbox((0, 0), word + " ", font=font)[2]
                current_word_count += 1
            y_text += 110 
            
        frames.append(np.array(img))
    
    return ImageSequenceClip(frames, fps=fps).set_duration(duration)

def merge_and_export(scene_list, output_name, audio_path, font_path="./fonts/UTM Kabel KT.ttf", color="#FFD700"):
    """
    Script ko clips ke beech split karke render karta hai
    """
    print(f"\n🎸 Master Audio & Script Splitting: {audio_path}")
    target_size = (1080, 1920)

    # 1. Master Audio load karein
    full_audio = AudioFileClip(audio_path)
    total_duration = full_audio.duration
    
    # 2. Script splitting logic
    full_text = scene_list[0]['text']
    words = full_text.split()
    # Har clip ke liye words calculate karein
    words_per_clip = max(1, len(words) // len(scene_list))
    
    clip_duration = total_duration / len(scene_list)
    final_combined_scenes = []

    for i, scene in enumerate(scene_list):
        # Video clip taiyaar karein
        v_clip = VideoFileClip(scene['video']).resize(height=target_size[1])
        if v_clip.w > target_size[0]:
            v_clip = v_clip.crop(x_center=v_clip.w/2, width=target_size[0])
        v_clip = v_clip.set_duration(clip_duration)

        # 3. Script ka part kaantein
        start_idx = i * words_per_clip
        # Last clip bacha hua saara text legi
        end_idx = (i + 1) * words_per_clip if i != len(scene_list) - 1 else len(words)
        clip_text_segment = " ".join(words[start_idx:end_idx])

        # 4. Sirf is segment ke liye subtitle banayein
        txt_clip = create_animated_text(clip_text_segment, target_size, clip_duration, font_path, color)
        
        # Video aur Segmented Subtitle merge karein
        scene_combined = CompositeVideoClip([v_clip, txt_clip.set_position('center')])
        final_combined_scenes.append(scene_combined)

    # 5. Saari clips ko jodein aur audio lagayein
    video_track = concatenate_videoclips(final_combined_scenes, method="compose").set_audio(full_audio)

    # 6. Background Music Logic
    try:
        music_dir = "./songs" if os.path.isdir("./songs") else "./songs copy"
        bg_music_files = [os.path.join(music_dir, f) for f in os.listdir(music_dir) if f.lower().endswith(('.mp3', '.wav'))]
        if bg_music_files:
            bg_music = AudioFileClip(random.choice(bg_music_files)).volumex(0.12).set_duration(total_duration)
            from moviepy.audio.AudioClip import CompositeAudioClip
            video_track = video_track.set_audio(CompositeAudioClip([video_track.audio, bg_music]))
    except: pass

    # Final Render
    video_track.write_videofile(output_name, codec="libx264", audio_codec="aac", fps=24)
    
    # Cleanup
    video_track.close()
    full_audio.close()
    for scene in final_combined_scenes: scene.close()
    
    return output_name