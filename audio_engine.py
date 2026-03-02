import os
import asyncio
import edge_tts

def make_audio(text, output_path):
    """
    MoneyPrinter style natural voice generator.
    Standard: hi-IN-MadhurNeural (Ek dum saaf Hindi aawaz)
    """
    print(f"🎙️ Advanced Voice ban rahi hai: {text[:30]}...")
    
    async def generate():
        # Aap 'hi-IN-SwaraNeural' bhi use kar sakte ho female voice ke liye
        communicate = edge_tts.Communicate(text, "hi-IN-MadhurNeural")
        await communicate.save(output_path)
    
    try:
        # Async function ko normal function ki tarah chalane ke liye
        asyncio.run(generate())
        if os.path.exists(output_path):
            return output_path
    except Exception as e:
        print(f"❌ Audio Engine Error: {e}")
        return None