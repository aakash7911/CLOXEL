from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uuid
import os

# Aapke modules
from video_editor import merge_and_export
from audio_engine import make_audio
from video_fetcher import fetch_video

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class VideoRequest(BaseModel):
    topic: str
    font_color: str = "yellow"
    voice_id: str = "hi-IN-MadhurNeural"

# Status track karne ke liye dictionary
jobs = {}

def process_video_task(job_id, topic, color, voice):
    try:
        # STEP 1: Audio status update
        jobs[job_id] = {"status": "Generating Audio..."}
        print(f"DEBUG: {job_id} - Audio shuru")
        a_path = f"audio_{job_id}.mp3"
        make_audio(f"Dosto kya aap jaante hain {topic}?", a_path, voice_id=voice)

        # STEP 2: Video Fetch status update
        jobs[job_id]["status"] = "Fetching Video..."
        print(f"DEBUG: {job_id} - Video fetching")
        v_path = f"video_{job_id}.mp4"
        fetch_video(topic, v_path)

        # STEP 3: Rendering status update
        jobs[job_id]["status"] = "Rendering Video..."
        print(f"DEBUG: {job_id} - Rendering")
        out_path = f"final_{job_id}.mp4"
        scene = [{"audio": a_path, "video": v_path, "text": topic}]
        merge_and_export(scene, out_path)

        if os.path.exists(out_path):
            # STEP 4: Final Success
            jobs[job_id] = {"status": "completed", "file": out_path}
            print(f"DEBUG: {job_id} - Completed!")
        else:
            raise Exception("File not created by editor")

    except Exception as e:
        print(f"DEBUG: {job_id} - Failed: {str(e)}")
        jobs[job_id] = {"status": "failed", "error": str(e)}

@app.post("/generate-custom-video")
async def generate(req: VideoRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    # Initial status
    jobs[job_id] = {"status": "Request Received"}
    background_tasks.add_task(process_video_task, job_id, req.topic, req.font_color, req.voice_id)
    return {"job_id": job_id}

@app.get("/status/{job_id}")
async def get_status(job_id: str):
    if job_id in jobs:
        return jobs[job_id]
    
    # Check karo agar file disk par ban chuki hai (Restart ke baad bhi)
    if os.path.exists(f"final_{job_id}.mp4"):
        return {"status": "completed"}
        
    return {"status": "Processing in background..."}

@app.get("/download/{job_id}")
async def download(job_id: str):
    job = jobs.get(job_id)
    if job and job.get("status") == "completed":
        return FileResponse(job["file"])
    return {"error": "Not ready"}




