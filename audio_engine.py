import cloudinary
import cloudinary.uploader
import edge_tts
import os
import uuid

# Cloudinary configuration (Render ke Environment Variables se uthayega)
cloudinary.config( 
  cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME"), 
  api_key = os.environ.get("CLOUDINARY_API_KEY"), 
  api_secret = os.environ.get("CLOUDINARY_API_SECRET") 
)

async def make_audio_and_get_link(text, filename, voice_id):
    # 1. Local audio file banayein
    communicate = edge_tts.Communicate(text, voice_id)
    await communicate.save(filename)
    
    # 2. Cloudinary par upload karein
    response = cloudinary.uploader.upload(filename, resource_type="video")
    
    # 3. Local file delete karein
    if os.path.exists(filename):
        os.remove(filename)
        
    # 4. Direct URL wapas bhejien
    return response['secure_url']
