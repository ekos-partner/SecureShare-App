import React, { useState } from 'react';
import { 
  Shield, 
  Code2, 
  Lock, 
  Key, 
  Copy, 
  Check,
  Zap,
  Globe,
  ArrowLeft,
  Menu,
  X
} from 'lucide-react';

export default function ApiDocs() {
  const [copied, setCopied] = useState<string | null>(null);
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const pythonCreateSnippet = `import requests
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def create_secure_secret(api_url, api_key, secret_text):
    # 1. Generate local key (NEVER sent to server)
    key = AESGCM.generate_key(bit_length=256)
    key_b64 = base64.urlsafe_b64encode(key).rstrip(b'=').decode('utf-8')
    
    # 2. Encrypt locally
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, secret_text.encode('utf-8'), None)
    
    # 3. Format payload (IV and Ciphertext as Base64)
    encrypted_data = f"{base64.b64encode(iv).decode('utf-8')}:{base64.b64encode(ciphertext).decode('utf-8')}"
    
    # 4. Send to API
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    payload = {
        "encryptedData": encrypted_data,
        "expirationHours": 24,
        "viewLimit": 1
    }
    
    response = requests.post(f"{api_url}/api/secrets", json=payload, headers=headers)
    response.raise_for_status() # Exit on error
    secret_id = response.json()["id"]
    
    # 5. Build E2EE link (key is in the URL fragment)
    return f"{api_url}/s/{secret_id}#{key_b64}"

# --- Usage ---
# Best Practice: Load from environment variables
API_URL = os.getenv("SECURESHARE_API_URL", "https://secureshare.example.com")
API_KEY = os.getenv("SECURESHARE_API_KEY")
SECRET_CONTENT = "db-password-123-xyz"

if not API_KEY:
    raise ValueError("SECURESHARE_API_KEY environment variable not set.")

secure_link = create_secure_secret(API_URL, API_KEY, SECRET_CONTENT)
print(f"Secure Link: {secure_link}")`;

const pythonRetrieveSnippet = `import requests
import base64
import os
from urllib.parse import urlparse, unquote
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def retrieve_and_decrypt_secret(secure_link):
    # 1. Parse Link to get ID and Key
    parsed_url = urlparse(secure_link)
    secret_id = parsed_url.path.split('/')[-1]
    key_b64 = parsed_url.fragment
    
    # Restore padding for Base64 decoding
    key = base64.urlsafe_b64decode(key_b64 + '==')
    
    # 2. Fetch encrypted data from API
    api_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    response = requests.get(f"{api_url}/api/secrets/{secret_id}")
    response.raise_for_status()
    
    encrypted_payload = response.json()["encryptedData"]
    iv_b64, ciphertext_b64 = encrypted_payload.split(':')
    
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    
    # 3. Decrypt locally
    aesgcm = AESGCM(key)
    decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
    
    return decrypted_bytes.decode('utf-8')

# --- Usage ---
import sys

if len(sys.argv) > 1:
    # Read link from command-line argument
    secure_link_from_cli = sys.argv[1]
    plaintext = retrieve_and_decrypt_secret(secure_link_from_cli)
    print(f"Decrypted Secret: {plaintext}")
else:
    print("Usage: python retrieve_secret.py <secure_link>")`;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-indigo-500/30">
      <div className="max-w-5xl mx-auto px-6 py-12 md:py-20">
        <header className="mb-16">
          <a href="/" className="inline-flex items-center gap-2 text-slate-500 hover:text-indigo-400 transition-colors mb-8 font-bold text-sm uppercase tracking-widest">
            <ArrowLeft className="w-4 h-4" /> Back to App
          </a>
          <div className="flex items-center gap-4 mb-6">
            <div className="p-3 bg-indigo-600 rounded-2xl">
              <Code2 className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-4xl md:text-5xl font-extrabold text-white tracking-tight">API Documentation</h1>
          </div>
          <p className="text-xl text-slate-400 max-w-2xl leading-relaxed">
            Integrate SecureShare into your existing workflows while maintaining 100% end-to-end encryption.
          </p>
        </header>

        <div className="lg:hidden mb-8">
          <button 
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            className="flex items-center gap-2 text-sm font-bold uppercase tracking-widest text-slate-400 hover:text-indigo-400 transition-colors p-2 rounded-lg bg-slate-900 border border-slate-800"
          >
            {isMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            Menu
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-12">
          {/* Sidebar Navigation */}
          <nav className={`${isMenuOpen ? 'block' : 'hidden'} lg:block lg:col-span-1 space-y-2 lg:sticky top-12 h-fit`}>
            <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-600 mb-4 ml-2">Getting Started</p>
            <NavItem href="#introduction" label="Introduction" />
            <NavItem href="#use-cases" label="Use Cases" />
            <NavItem href="#server-targeting" label="Server Targeting" />
            <NavItem href="#authentication" label="Authentication" />
            <NavItem href="#encryption" label="Encryption Flow" />
            <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-600 mt-8 mb-4 ml-2">Endpoints</p>
            <NavItem href="#create-secret" label="POST Create Secret" />
            <NavItem href="#get-metadata" label="GET Metadata" />
            <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-600 mt-8 mb-4 ml-2">Full E2EE Examples</p>
            <NavItem href="#python-create" label="Python: Create" />
            <NavItem href="#python-retrieve" label="Python: Retrieve" />
          </nav>

          {/* Main Content */}
          <div className="lg:col-span-3 space-y-24">
            <section id="introduction">
              <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
                <Zap className="w-6 h-6 text-amber-400" /> Introduction
              </h2>
              <div className="prose prose-invert prose-slate max-w-none">
                <p className="text-slate-400 leading-relaxed text-lg">
                  The SecureShare API allows you to programmatically create and manage encrypted secrets. 
                  Our API is designed with a <strong className="text-white">Zero-Knowledge architecture</strong>: the server never sees the raw content of your secrets.
                </p>
                <div className="mt-8 p-6 bg-indigo-900/10 border border-indigo-900/30 rounded-3xl">
                  <h3 className="text-indigo-400 font-bold mb-2 flex items-center gap-2">
                    <Shield className="w-5 h-5" /> The Golden Rule
                  </h3>
                  <p className="text-sm text-slate-300 leading-relaxed">
                    All encryption <strong>must</strong> happen on your side (the client). Do not send plaintext data to the API. 
                    Always use AES-256-GCM for encryption.
                  </p>
                </div>
              </div>
            </section>

            <section id="use-cases">
               <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
                 <Zap className="w-6 h-6 text-amber-400" /> Practical Use Cases
               </h2>
               <div className="space-y-6">
                 <UseCase
                   title="CI/CD Pipelines"
                   description="Securely pass temporary credentials like database passwords or cloud access keys from a build server to a deployment script without exposing them in logs."
                 />
                 <UseCase
                   title="Automated Employee Onboarding"
                   description="An HR system automatically generates a secure link with a new employee's initial password and sends it to their personal email, ensuring privacy."
                 />
                 <UseCase
                   title="Incident Response & Support"
                   description="Share temporary access credentials with an on-call engineer or support agent without pasting sensitive data into Slack, Teams, or ticketing systems."
                 />
               </div>
            </section>

            <section id="server-targeting">
                <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
                  <Globe className="w-6 h-6 text-cyan-400" /> Server Targeting & Best Practices
                </h2>
                <div className="prose prose-invert prose-slate max-w-none">
                  <p className="text-slate-400 leading-relaxed">
                    All API requests should be made to the base URL of your SecureShare instance. For reliability and security, we strongly recommend managing the API endpoint and your key using environment variables rather than hardcoding them in your scripts.
                  </p>
                  <div className="bg-slate-900 rounded-2xl p-4 font-mono text-sm border border-slate-800 mt-4">
                    <span className="text-slate-500"># Example .env file or environment variables</span>
                    <br />
                    <span className="text-amber-400">SECURESHARE_API_URL</span><span className="text-slate-500">=</span><span className="text-emerald-400">"https://your-secureshare-instance.com"</span>
                    <br />
                    <span className="text-amber-400">SECURESHARE_API_KEY</span><span className="text-slate-500">=</span><span className="text-emerald-400">"your_api_key_here"</span>
                  </div>
                </div>
             </section>

            <section id="authentication">
              <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
                <Lock className="w-6 h-6 text-indigo-400" /> Authentication
              </h2>
              <p className="text-slate-400 mb-6">
                Authenticate your requests by including your API key in the <code className="text-indigo-400 bg-indigo-400/10 px-1.5 py-0.5 rounded">X-API-Key</code> header.
              </p>
              <div className="bg-slate-900 rounded-2xl p-4 font-mono text-sm border border-slate-800">
                <span className="text-slate-500">X-API-Key:</span> <span className="text-emerald-400">your_key_id.your_raw_secret_key</span>
              </div>
              <p className="mt-4 text-sm text-slate-500 italic">
                * API keys can be generated in the Admin Dashboard.
              </p>
            </section>

            <section id="encryption">
              <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
                <Key className="w-6 h-6 text-emerald-400" /> Encryption Flow
              </h2>
              <div className="space-y-8">
                <Step number="01" title="Generate Key" description="Generate a random 256-bit AES key locally." />
                <Step number="02" title="Encrypt Data" description="Encrypt your secret using AES-256-GCM with a random 12-byte IV." />
                <Step number="03" title="Format Payload" description="Base64 encode the IV and Ciphertext, then join them with a colon (IV:Ciphertext)." />
                <Step number="04" title="API Request" description="Send the encrypted payload to the server. The server returns a unique ID." />
                <Step number="05" title="Build Link" description="Construct the final URL: https://domain.com/s/{ID}#{KEY}. The key is in the fragment, so it's never sent back to the server." />
              </div>
            </section>

            <section id="create-secret">
              <h2 className="text-2xl font-bold text-white mb-6">POST /api/secrets</h2>
              <p className="text-slate-400 mb-6">Create a new encrypted secret.</p>
              
              <div className="space-y-4">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-1 bg-emerald-900/20 text-emerald-400 text-[10px] font-bold rounded border border-emerald-900/30">POST</span>
                  <code className="text-slate-300">/api/secrets</code>
                </div>
                
                <div className="bg-slate-900 rounded-2xl border border-slate-800 overflow-hidden">
                  <div className="p-4 bg-slate-800/50 border-b border-slate-800 flex justify-between items-center">
                    <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">Request Body (JSON)</span>
                    <button onClick={() => copyToClipboard('{\n  "encryptedData": "iv:ciphertext",\n  "expirationHours": 24,\n  "viewLimit": 1\n}', 'req')} className="text-slate-500 hover:text-white transition-colors">
                      {copied === 'req' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                  <pre className="p-6 text-sm font-mono text-indigo-300 overflow-x-auto">
{`{
  "encryptedData": "base64_iv:base64_ciphertext",
  "expirationHours": 24,
  "viewLimit": 1,
  "passwordHash": "optional_sha256_hash",
  "salt": "optional_base64_salt"
}`}
                  </pre>
                </div>
              </div>
            </section>

            <section id="python-create">
              <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
                <Globe className="w-6 h-6 text-blue-400" /> Python: Create Secret
              </h2>
              <div className="bg-slate-900 rounded-2xl border border-slate-800 overflow-hidden">
                <div className="p-4 bg-slate-800/50 border-b border-slate-800 flex justify-between items-center">
                  <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">create_secret.py</span>
                  <button onClick={() => copyToClipboard(pythonCreateSnippet, 'py_create')} className="text-slate-500 hover:text-white transition-colors">
                    {copied === 'py_create' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
                <pre className="p-6 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed">
                  {pythonCreateSnippet}
                </pre>
              </div>
            </section>

            <section id="python-retrieve">
              <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
                <Globe className="w-6 h-6 text-emerald-400" /> Python: Retrieve & Decrypt Secret
              </h2>
              <div className="bg-slate-900 rounded-2xl border border-slate-800 overflow-hidden">
                <div className="p-4 bg-slate-800/50 border-b border-slate-800 flex justify-between items-center">
                  <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">retrieve_secret.py</span>
                  <button onClick={() => copyToClipboard(pythonRetrieveSnippet, 'py_retrieve')} className="text-slate-500 hover:text-white transition-colors">
                    {copied === 'py_retrieve' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
                <pre className="p-6 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed">
                  {pythonRetrieveSnippet}
                </pre>
              </div>
            </section>
          </div>
        </div>

        <footer className="mt-32 pt-12 border-t border-slate-900 text-center">
          <p className="text-slate-600 text-sm">
            SecureShare API v1.1.0 &bull; Built for Privacy
          </p>
        </footer>
      </div>
    </div>
  );
}

function NavItem({ href, label }: { href: string, label: string }) {
  return (
    <a 
      href={href} 
      className="block px-4 py-2 text-sm font-medium text-slate-500 hover:text-indigo-400 hover:bg-indigo-500/5 rounded-xl transition-all"
    >
      {label}
    </a>
  );
}

function UseCase({ title, description }: { title: string, description: string }) {
  return (
    <div className="p-5 bg-slate-900 border border-slate-800 rounded-2xl">
      <h4 className="text-white font-bold mb-1">{title}</h4>
      <p className="text-slate-500 text-sm leading-relaxed">{description}</p>
    </div>
  );
}

function Step({ number, title, description }: { number: string, title: string, description: string }) {
  return (
    <div className="flex gap-6">
      <div className="text-indigo-500 font-mono font-bold text-lg">{number}</div>
      <div>
        <h4 className="text-white font-bold mb-1">{title}</h4>
        <p className="text-slate-500 text-sm leading-relaxed">{description}</p>
      </div>
    </div>
  );
}
