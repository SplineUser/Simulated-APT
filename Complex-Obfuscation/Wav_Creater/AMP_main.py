import wave
import numpy as np

def bcd_to_wav(bcd_string, filename='output.wav', bit_duration=0.0025, sample_rate=44100):
    amplitude = 30000  # Amplitude for '1' bits
    samples_per_bit = int(sample_rate * bit_duration)

    audio_data = []

    for bit in bcd_string:
        if bit == '1':
            samples = [amplitude] * samples_per_bit
        else:
            samples = [0] * samples_per_bit
        audio_data.extend(samples)

    # Convert to numpy int16
    audio_np = np.array(audio_data, dtype=np.int16)

    # Write to .wav file
    with wave.open(filename, 'w') as wav_file:
        wav_file.setnchannels(1)             # mono
        wav_file.setsampwidth(2)             # 16-bit
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(audio_np.tobytes())

    print(f"[+] WAV file written: {filename} | Duration: {len(audio_np)/sample_rate:.2f}s")

# Example usage
if __name__ == "__main__":
    # ASCII 'AB' in BCD is: '01000001 01000010'
    bcd_string = '000100 001011 RED'
    bcd_string = bcd_string.replace(" ", "")
    bcd_to_wav(bcd_string, 'shellcode.wav')    
