import requests
import os

PEXELS_API_KEY = os.environ.get("PEXELS_API_KEY")

def get_video_assets(topic, count=5):
    url = f"https://api.pexels.com/videos/search?query={topic}&per_page={count}"
    headers = {"Authorization": PEXELS_API_KEY}
    
    response = requests.get(url, headers=headers)
    data = response.json()
    
    video_links = []
    if "videos" in data:
        for video in data["videos"]:
            # Sabse acchi quality wali link nikalna
            files = video.get("video_files", [])
            if files:
                video_links.append(files[0].get("link"))
                
    return video_links
