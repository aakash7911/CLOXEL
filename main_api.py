from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid

# Modules
from audio_engine import make_audio_and_get_link 
from video_fetcher import get_video_assets 

app = FastAPI()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Naya Request Model (Android se match karne ke liye)
class VideoRequest(BaseModel):
    script: str
    topic: str
    duration: int = 30
    voice_id: str = "en-US-AndrewMultilingualNeural"
    font_name: str = "Arial"   # Naya parameter
    font_color: str = "#FFFFFF" # Naya parameter

@app.post("/generate")
async def generate(req: VideoRequest):
    job_id = str(uuid.uuid4())
    
    try:
        print(f"Generating for topic: {req.topic} with font: {req.font_name}")

        # 1. Audio generate karo (Aapka existing Cloudinary logic)
        audio_url = await make_audio_and_get_link(req.script, f"voice_{job_id}.mp3", req.voice_id)
        
        # 2. Pexels se video clips nikaalo
        video_urls = get_video_assets(req.topic, count=5)

        # 3. Phone App ko sara data wapas bhejo
        # Hum 'font_name' aur 'font_color' bhi assets mein bhej rahe hain taaki Android use read kare
        return {
            "status": "success",
            "job_id": job_id,
            "assets": {
                "audio_url": audio_url,
                "video_urls": video_urls,
                "script": req.script,
                "font_name": req.font_name,
                "font_color": req.font_color
            }
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return {"status": "failed", "error": str(e)}
