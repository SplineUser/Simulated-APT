import numpy as np
import soundfile as sf

def bcd_to_wav(bcd_data, filename='lilshellcode.wav', bit_duration=0.005, sample_rate=44100):
    t = np.linspace(0, bit_duration, int(sample_rate * bit_duration), endpoint=False)
    signal = np.array([])
    
    for bit in bcd_data:
        freq = 3000 if bit == '1' else 2000  # Wider frequency gap
        tone = 0.5 * np.sin(2 * np.pi * freq * t)
        signal = np.concatenate((signal, tone))
    
    sf.write(filename, signal, sample_rate)

# Usage
bcd+string = '0101010 0101010 REDACTED'
bcd_string = bcd_string.replace(" ", "")
bcd_to_wav(bcd_string, "shellcode_fast.wav")
print("File created successfully")
