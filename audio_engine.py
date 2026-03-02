import os
import asyncio
import edge_tts

def make_audio(text, output_path, voice_id="hi-IN-MadhurNeural"):
    """
    Ab ye 'voice_id' ko accept karega, jo pichle error ki wajah thi.
    Default voice Madhur rakhi hai agar koi choice na mile.
    """
    print(f"🎙️ Advanced Voice ban rahi hai ({voice_id}): {text[:30]}...")
    
    async def generate():
        # Yahan fixed voice ki jagah variable 'voice_id' use hoga
        communicate = edge_tts.Communicate(text, voice_id)
        await communicate.save(output_path)
    
    try:
        # Async loop manage karne ke liye try-except zaroori hai
        asyncio.run(generate())
        if os.path.exists(output_path):
            return output_path
    except Exception as e:
        print(f"❌ Audio Engine Error: {e}")
        return None
