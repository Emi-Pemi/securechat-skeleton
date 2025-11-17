#"""Append-only transcript + TranscriptHash helpers.""" 
#raise NotImplementedError("students: implement transcript layer")

"""Append-only transcript management for non-repudiation."""

import os
import hashlib
from datetime import datetime


class TranscriptManager:
    """Manage append-only session transcripts for non-repudiation."""
    
    def __init__(self, role: str, session_id: str = None):
        """
        Initialize transcript manager.
        
        Args:
            role: "client" or "server"
            session_id: Unique session identifier (timestamp-based if None)
        """
        self.role = role
        self.session_id = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.entries = []
        
        # Create transcripts directory if it doesn't exist
        os.makedirs("transcripts", exist_ok=True)
        
        # Transcript filename
        self.filename = f"transcripts/{self.role}_{self.session_id}.txt"
        
        # Open file in append mode
        self.file = open(self.filename, 'a')
        
        print(f"[+] Transcript: {self.filename}")
    
    def add_entry(self, seqno: int, timestamp: int, ciphertext: str, signature: str, peer_cert_fingerprint: str):
        """
        Add entry to transcript.
        
        Format: seqno | timestamp | ciphertext | signature | peer_cert_fingerprint
        
        Args:
            seqno: Message sequence number
            timestamp: Unix timestamp in milliseconds
            ciphertext: Base64-encoded ciphertext
            signature: Base64-encoded RSA signature
            peer_cert_fingerprint: SHA-256 fingerprint of peer's certificate
        """
        entry = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_cert_fingerprint}\n"
        
        # Write to file immediately (append-only)
        self.file.write(entry)
        self.file.flush()  # Ensure written to disk
        
        # Store in memory for hash computation
        self.entries.append(entry)
    
    def compute_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of entire transcript.
        
        Returns:
            Hex string of transcript hash
        """
        # Concatenate all entries
        transcript_data = ''.join(self.entries).encode('utf-8')
        
        # Compute SHA-256 hash
        return hashlib.sha256(transcript_data).hexdigest()
    
    def get_sequence_range(self) -> tuple[int, int]:
        """
        Get first and last sequence numbers in transcript.
        
        Returns:
            tuple: (first_seq, last_seq)
        """
        if not self.entries:
            return 0, 0
        
        # Extract sequence numbers from entries
        first_seqno = int(self.entries[0].split('|')[0])
        last_seqno = int(self.entries[-1].split('|')[0])
        
        return first_seqno, last_seqno
    
    def save_receipt(self, receipt_data: str, signature: str):
        """
        Save session receipt to file.
        
        Args:
            receipt_data: Receipt JSON string
            signature: Base64-encoded signature
        """
        receipt_filename = f"transcripts/{self.role}_{self.session_id}_receipt.json"
        
        with open(receipt_filename, 'w') as f:
            f.write(receipt_data)
        
        print(f"[+] Session receipt saved: {receipt_filename}")
    
    def close(self):
        """Close transcript file."""
        if self.file:
            self.file.close()
            print(f"[+] Transcript closed: {self.filename}")
    
    def __del__(self):
        """Ensure file is closed on deletion."""
        if hasattr(self, 'file') and self.file:
            self.file.close()


def verify_transcript_offline(transcript_path: str, expected_hash: str) -> bool:
    """
    Verify transcript integrity offline by recomputing hash.
    
    Args:
        transcript_path: Path to transcript file
        expected_hash: Expected SHA-256 hash (hex string)
    
    Returns:
        True if hash matches, False otherwise
    """
    try:
        with open(transcript_path, 'r') as f:
            transcript_data = f.read().encode('utf-8')
        
        computed_hash = hashlib.sha256(transcript_data).hexdigest()
        
        return computed_hash == expected_hash
        
    except Exception as e:
        print(f"[!] Error verifying transcript: {e}")
        return False
