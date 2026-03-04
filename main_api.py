from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid
import os

# Modules (Sirf audio aur fetcher chahiye, editor nahi)
from audio_engine import make_audio_and_get_link # Cloudinary wala function
from video_fetcher import get_video_assets # Sirf links wala function

app = FastAPI()

# CORS taaki Android app se connect ho sake
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class VideoRequest(BaseModel):
    script: str
    topic: str
    duration: int
    voice_id: str

@app.post("/generate")
async def generate(req: VideoRequest):
    job_id = str(uuid.uuid4())
    
    try:
        # 1. Audio generate karo aur Cloudinary link lo
        audio_url = await make_audio_and_get_link(req.script, f"voice_{job_id}.mp3", req.voice_id)
        
        # 2. Pexels se sirf video URLs ki list nikaalo
        # Dynamic Clip Count Logic
        d = req.duration
        if d <= 15: clip_count = 2
        elif d <= 30: clip_count = 4
        elif d <= 40: clip_count = 5
        elif d <= 50: clip_count = 7
        else: clip_count = 10 

        video_urls = get_video_assets(req.topic, count=clip_count)

        # 3. Phone App ko sara saman JSON mein bhej do
        return {
            "status": "success",
            "job_id": job_id,
            "assets": {
                "audio_url": audio_url,
                "video_urls": video_urls,
                "script": req.script
            }
        }
        
    except Exception as e:
        return {"status": "failed", "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
