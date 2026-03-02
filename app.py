from audio_engine import make_audio
from video_fetcher import fetch_video
from video_editor import merge_and_export

def main():
    print("\n🚀 --- Zobbly Manual Engine (No-API Mode) ---")
    
    # Aapke manual scenes
    scenes = [
        {
            "text": "Dosto, kya aap jaante hain ki antariksh kitna bada hai?", 
            "keyword": "galaxy"
        },
        {
            "text": "Yahan har pal naye taare bante aur khatam hote hain.", 
            "keyword": "stars"
        },
        {
            "text": "Hamari dharti is brahmand ka ek chota sa hissa hai.", 
            "keyword": "earth space"
        }
    ]
    
    taiyaar_scenes = [] 
    
    for i, scene in enumerate(scenes):
        print(f"\n🎬 Scene {i+1} ki taiyari...")
        
        # 1. Voice generate ho rahi hai
        audio = make_audio(scene["text"], f"voice_{i}.mp3")
        
        # 2. Video download ho rahi hai
        video = fetch_video(scene["keyword"], f"video_{i}.mp4")
        
        if audio and video:
            # FIX: Yahan 'text' pass kar rahe hain subtitles ke liye
            taiyaar_scenes.append({
                "audio": audio, 
                "video": video,
                "text": scene["text"]  # <-- Ye zaroori tha
            })
        else:
            print(f"⏭️ Scene {i+1} skip kiya gaya data na milne ki wajah se.")
            
    if taiyaar_scenes:
        print("\n🔗 Sab clips ko ek saath joda ja raha hai...")
        # FFmpeg mixing aur subtitles apply honge
        merge_and_export(taiyaar_scenes, "zobbly_manual_video.mp4")
        print("\n✅ Video successfully ban gayi: zobbly_manual_video.mp4")
    else:
        print("❌ Ek bhi scene taiyaar nahi ho paya!")

if __name__ == "__main__":
    main()