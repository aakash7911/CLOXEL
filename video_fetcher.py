import os
import requests
from dotenv import load_dotenv

# Local development ke liye .env file load karega (Optional)
load_dotenv()

# === RENDER SE API KEY UTHAYEGA ===
# Render ke Dashboard mein Variable Name: PEXELS_API_KEY daalna
PEXELS_API_KEY = os.getenv("PEXELS_API_KEY")

def fetch_video(keyword, filename):
    if not PEXELS_API_KEY:
        print("❌ Error: PEXELS_API_KEY nahi mili! Render settings check karein.")
        return None

    print(f"📥 Pexels se '{keyword}' dhoondha ja raha hai...")
    headers = {"Authorization": PEXELS_API_KEY}
    url = f"https://api.pexels.com/videos/search?query={keyword}&per_page=1&orientation=portrait"
    
    try:
        response = requests.get(url, headers=headers).json()
        
        if 'videos' in response and len(response['videos']) > 0:
            video_url = response['videos'][0]['video_files'][0]['link']
            print(f"✅ Video mil gayi! Download shuru...")
            
            vid_data = requests.get(video_url).content
            with open(filename, "wb") as f:
                f.write(vid_data)
            return filename
        else:
            print(f"⚠️ Warning: '{keyword}' ke liye koi video nahi mili.")
            return None
            
    except Exception as e:
        print(f"❌ Network Error: {e}")
        return None
