from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uuid
import os

# Modules check
from video_editor import merge_and_export
from audio_engine import make_audio
from video_fetcher import fetch_videos 

app = FastAPI()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class VideoRequest(BaseModel):
    script: str
    topic: str
    duration: int
    font_name: str
    text_color: str
    voice_id: str

jobs = {}

def process_video_task(job_id, data: VideoRequest):
    try:
        jobs[job_id] = {"status": "Generating Master Audio..."}
        a_path = f"voice_{job_id}.mp3"
        out_path = f"final_{job_id}.mp4"

        # 1. Poora Audio ek saath generate karein
        make_audio(data.script, a_path, voice_id=data.voice_id)
        
        # 2. Dynamic Clip Count Logic (Aapka bataya hua logic)
        d = data.duration
        if d <= 15: clip_count = 2
        elif d <= 30: clip_count = 4
        elif d <= 40: clip_count = 5
        elif d <= 50: clip_count = 7
        else: clip_count = 10 

        # 3. Pexels se Multiple Clips laayein
        jobs[job_id]["status"] = f"Fetching {clip_count} clips for {d}s video..."
        video_clips = fetch_videos(data.topic, job_id, count=clip_count)

        if not video_clips:
            raise Exception("Videos download nahi ho payin")

        # 4. Scene list taiyaar karein (Ab audio path yahan se hat gaya hai)
        jobs[job_id]["status"] = "Master Sync Rendering..."
        scene_list = []
        for v_path in video_clips:
            scene_list.append({
                "video": v_path,
                "text": data.script
            })
        
        # 5. Merge and Export (Audio path alag se pass ho raha hai)
        merge_and_export(
            scene_list, 
            out_path, 
            audio_path=a_path, # FIX: Master audio track
            font_path=f"./fonts/{data.font_name}", 
            color=data.text_color
        ) 

        jobs[job_id] = {"status": "completed", "file": out_path}
        
    except Exception as e:
        print(f"❌ API Error: {e}")
        jobs[job_id] = {"status": "failed", "error": str(e)}

@app.post("/generate")
async def generate(req: VideoRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "queued"}
    background_tasks.add_task(process_video_task, job_id, req)
    return {"job_id": job_id}

@app.get("/status/{job_id}")
async def get_status(job_id: str):
    return jobs.get(job_id, {"status": "not_found"})

@app.get("/download/{job_id}")
async def download(job_id: str):
    job = jobs.get(job_id)
    if job and job.get("status") == "completed":
        return FileResponse(job["file"])
    return {"error": "File not ready"}

if __name__ == "__main__":
    import uvicorn
    # Local Network (Phone) ke liye
    uvicorn.run(app, host="0.0.0.0", port=8000)