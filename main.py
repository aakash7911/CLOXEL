import os
import uuid
import shutil
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Aapke modules
from video_editor import merge_and_export
from audio_engine import make_audio
from video_fetcher import fetch_video

app = FastAPI()

# 1. CORS Setup - Iske bina frontend connect nahi hoga!
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

class VideoRequest(BaseModel):
    topic: str
    font_name: str = "UTM Kabel KT.ttf"
    font_color: str = "yellow"
    voice_id: str = "hi-IN-MadhurNeural"
    language: str = "hi"

# In-memory job status (Production mein Redis/DB use karna)
jobs = {}

def full_process(req: VideoRequest, job_id: str):
    """Asli logic jo background mein chalega"""
    try:
        # User ke liye ek alag folder banate hain taaki kachra mix na ho
        job_dir = f"temp_{job_id}"
        os.makedirs(job_dir, exist_ok=True)
        
        # Scenes ki taiyari (Example: 2 scenes, aap ise AI se bhi judwa sakte hain)
        scenes_data = [
            {"text": f"Dosto, aaj hum {req.topic} ke baare mein baat karenge.", "keyword": req.topic},
            {"text": "Ye jankari aapko kaisi lagi? Comment mein batayein.", "keyword": "cool facts"}
        ]
        
        taiyaar_scenes = []
        for i, sc in enumerate(scenes_data):
            a_path = os.path.join(job_dir, f"audio_{i}.mp3")
            v_path = os.path.join(job_dir, f"video_{i}.mp4")
            
            # Custom settings apply karna
            make_audio(sc["text"], a_path) # Voice ID logic aapke audio engine mein handle hoga
            fetch_video(sc["keyword"], v_path)
            
            if os.path.exists(a_path) and os.path.exists(v_path):
                taiyaar_scenes.append({
                    "audio": a_path, 
                    "video": v_path, 
                    "text": sc["text"]
                })

        if taiyaar_scenes:
            output_file = f"output_{job_id}.mp4"
            # Editor ko user ki choice bhejna (font, color)
            merge_and_export(taiyaar_scenes, output_file) 
            jobs[job_id] = {"status": "completed", "file": output_file, "dir": job_dir}
        else:
            jobs[job_id] = {"status": "failed", "error": "No scenes ready"}

    except Exception as e:
        print(f"❌ Error in full_process: {e}")
        jobs[job_id] = {"status": "failed", "error": str(e)}

@app.post("/generate-custom-video")
async def generate_custom_video(req: VideoRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "processing"}
    background_tasks.add_task(full_process, req, job_id)
    return {"job_id": job_id, "status": "Processing Started"}

@app.get("/status/{job_id}")
async def get_status(job_id: str):
    return jobs.get(job_id, {"status": "not_found"})

@app.get("/download/{job_id}")
async def download_video(job_id: str):
    job = jobs.get(job_id)
    if job and job["status"] == "completed":
        return FileResponse(job["file"], media_type="video/mp4", filename="zobbly_reel.mp4")
    return {"error": "File not ready"}

@app.post("/cleanup/{job_id}")
async def cleanup(job_id: str):
    """Video download hone ke baad server saaf karne ke liye"""
    job = jobs.get(job_id)
    if job:
        if os.path.exists(job.get("file", "")): os.remove(job["file"])
        if os.path.exists(job.get("dir", "")): shutil.rmtree(job["dir"])
        return {"status": "Cleaned"}
    return {"error": "Job not found"}
