# CyberScan AI - Replace Ollama with Anthropic
Status: In Progress

## Approved Plan Breakdown

### 1. [x] Create TODO.md (Current - Done)
### 2. [x] Update requirements.txt
   - Add/uncomment `anthropic>=0.25.0`

### 3. [x] Update server.py
   - Import anthropic, set HAS_ANTHROPIC=True
   - Add _call_anthropic() using AnthropicAsyncClient
   - Update call_ai() to prefer Anthropic if vault key present
   - Add anthropic_key to VaultReq and /api/vault
   - Update /health capabilities reporting

### 4. [x] Minor index.html update
   - Update Quodo status text for Anthropic

### 5. [x] Install dependencies
   - `pip install anthropic>=0.25.0`

### 6. [ ] Test integration
   - Restart server: `python server.py`
   - Add Anthropic API key to vault
   - Test /api/chat endpoint
   - Verify frontend chat works with Claude

### 7. [ ] Update TODO.md & attempt_completion

