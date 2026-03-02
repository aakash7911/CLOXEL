import requests

# === APNI PEXELS KEY YAHAN DAALO ===
PEXELS_API_KEY = "jqGZN1a4uHQFpxqdFAdVaD1l1eyjW1kzHqtdlNJ1TPkSmOEXcbAL7yhN"

def fetch_video(keyword, filename):
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