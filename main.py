from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uuid
import os

# Aapke existing modules
from video_editor import merge_and_export
from audio_engine import make_audio
from video_fetcher import fetch_video

app = FastAPI()

# SABSE ZAROORI: Browser block na kare isliye CORS jod rahe hain
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class VideoRequest(BaseModel):
    topic: str
    font_color: str = "yellow"
    voice_id: str = "hi-IN-MadhurNeural"

jobs = {}

def process_video_task(job_id, topic, color, voice):
    try:
        jobs[job_id]["status"] = "Generating Audio..."
        a_path = f"audio_{job_id}.mp3"
        v_path = f"video_{job_id}.mp4"
        out_path = f"final_{job_id}.mp4"

        # 1. Voice bnao
        make_audio(f"Dosto kya aap jaante hain {topic} ke baare mein?", a_path, voice_id=voice)
        
        # 2. Video fetch karo
        jobs[job_id]["status"] = "Fetching Video..."
        fetch_video(topic, v_path)

        # 3. Merge karo
        jobs[job_id]["status"] = "Rendering Video..."
        scene = [{"audio": a_path, "video": v_path, "text": f"Dosto kya aap jaante hain {topic}?"}]
        merge_and_export(scene, out_path)

        if os.path.exists(out_path):
            jobs[job_id] = {"status": "completed", "file": out_path}
        else:
            jobs[job_id] = {"status": "failed", "error": "Editor failed to create file"}
            
    except Exception as e:
        jobs[job_id] = {"status": "failed", "error": str(e)}

@app.get("/")
def home():
    return {"message": "Zobbly AI Server is Running! 🚀"}

@app.post("/generate-custom-video")
async def generate(req: VideoRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "started"}
    background_tasks.add_task(process_video_task, job_id, req.topic, req.font_color, req.voice_id)
    return {"job_id": job_id}

@app.get("/status/{job_id}")
async def get_status(job_id: str):
    return jobs.get(job_id, {"status": "not_found"})

@app.get("/download/{job_id}")
async def download(job_id: str):
    job = jobs.get(job_id)
    if job and job.get("status") == "completed":
        return FileResponse(job["file"])
    return {"error": "Not ready"}

