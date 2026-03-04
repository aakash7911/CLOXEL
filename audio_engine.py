import asyncio
import edge_tts
import os
import random

def make_audio(text, output_path, voice_id='hi-IN-MadhurNeural'):
    print(f"🎙️ Generating Voice: {text[:30]}...")
    
    async def amain():
        try:
            # Random delay taki rate-limit na ho
            await asyncio.sleep(random.uniform(1.5, 3.0))
            
            communicate = edge_tts.Communicate(text, voice_id)
            await communicate.save(output_path)
            print(f"✅ Audio saved: {output_path}")
        except Exception as e:
            if "403" in str(e):
                print(f"⚠️ Microsoft ne block kiya (403). Changing strategy...")
                # Yahan hum retry limit badha sakte hain ya pause le sakte hain
            raise e

    try:
        asyncio.run(amain())
        if os.path.exists(output_path):
            return output_path
    except Exception as e:
        print(f"❌ Audio Engine Failed Final: {e}")
        return None