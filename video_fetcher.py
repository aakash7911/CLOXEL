import requests
import os

# === APNI PEXELS KEY YAHAN DAALO ===
PEXELS_API_KEY = "jqGZN1a4uHQFpxqdFAdVaD1l1eyjW1kzHqtdlNJ1TPkSmOEXcbAL7yhN"

def fetch_videos(keyword, job_id, count=1):
    """
    Ek se zyada videos download karne ke liye logic
    """
    print(f"📥 Pexels se '{keyword}' ke liye {count} clips dhoondhi ja rahi hain...")
    headers = {"Authorization": PEXELS_API_KEY}
    
    # Per_page mein hum 'count' bhej rahe hain
    url = f"https://api.pexels.com/videos/search?query={keyword}&per_page={count}&orientation=portrait"
    
    try:
        response = requests.get(url, headers=headers).json()
        video_paths = []
        
        if 'videos' in response and len(response['videos']) > 0:
            for i, video_data in enumerate(response['videos']):
                video_url = video_data['video_files'][0]['link']
                filename = f"clip_{job_id}_{i}.mp4" # Har clip ka unique naam
                
                print(f"✅ Clip {i+1} mil gayi! Downloading...")
                vid_data = requests.get(video_url).content
                with open(filename, "wb") as f:
                    f.write(vid_data)
                video_paths.append(filename)
                
            return video_paths
        else:
            print(f"⚠️ Warning: '{keyword}' ke liye videos nahi mili.")
            return []
            
    except Exception as e:
        print(f"❌ Network Error: {e}")
        return []