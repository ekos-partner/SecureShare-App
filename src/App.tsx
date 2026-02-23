/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  Lock, 
  Clock, 
  Eye, 
  Copy, 
  Check, 
  AlertCircle, 
  RefreshCw, 
  Link as LinkIcon,
  Trash2,
  ChevronRight,
  ShieldAlert,
  Info,
  X,
  EyeOff
} from 'lucide-react';
import { encryptSecret, decryptSecret, hashPassword } from './lib/crypto';
import clsx, { type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { QRCodeSVG } from 'qrcode.react';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type ViewState = 'create' | 'success' | 'view' | 'error';

const getPasswordStrength = (pwd: string) => {
  if (!pwd) return 0;
  let strength = 0;
  if (pwd.length >= 6) strength++;
  if (pwd.length >= 10) strength++;
  if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) strength++;
  if (/[0-9]/.test(pwd)) strength++;
  if (/[^A-Za-z0-9]/.test(pwd)) strength++;
  return Math.min(strength, 4);
};

/**
 * Helper to get password strength color based on level
 */
const getPasswordStrengthColor = (strength: number, level: number) => {
  if (strength < level) return "bg-slate-200 dark:bg-slate-800";
  
  const colors: Record<number, string> = {
    1: "bg-red-500",
    2: "bg-orange-500",
    3: "bg-yellow-500",
    4: "bg-emerald-500"
  };
  
  return colors[strength] || "bg-emerald-500";
};

/**
 * Helper to get password strength label
 */
const getPasswordStrengthLabel = (strength: number) => {
  const labels: Record<number, string> = {
    1: "Weak",
    2: "Fair",
    3: "Good",
    4: "Strong"
  };
  
  return labels[strength] || "";
};

const getAppOrigin = () => {
  try {
    return (window.location.origin && window.location.origin !== 'null') 
      ? window.location.origin 
      : (window.location.protocol + '//' + window.location.host);
  } catch {
    return window.location.protocol + '//' + window.location.host;
  }
};

const validateGenerateResponse = (res: Response) => {
  if (!res.ok) {
    if (res.status === 429) {
      const retryAfter = res.headers.get('Retry-After');
      const waitMsg = retryAfter ? ` Please wait ${Math.ceil(Number.parseInt(retryAfter, 10) / 60)} minute(s).` : ' Please wait a while.';
      throw new Error('Creation limit reached.' + waitMsg);
    }
    throw new Error('Failed to generate link');
  }
};

export default function App() {
  /**
   * APPLICATION STATE
   * We use React hooks to manage the UI state, form inputs, and API responses.
   */
  const [view, setView] = useState<ViewState>('create');
  const [secret, setSecret] = useState('');
  const [password, setPassword] = useState('');
  const [expiration, setExpiration] = useState('24');
  const [viewLimit, setViewLimit] = useState('1');
  const [generatedLink, setGeneratedLink] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [showQR, setShowQR] = useState(false);
  
  // For viewing
  const [viewId, setViewId] = useState('');
  const [viewKey, setViewKey] = useState('');
  const [viewEncryptedData, setViewEncryptedData] = useState('');
  const [viewHasPassword, setViewHasPassword] = useState(false);
  const [viewSalt, setViewSalt] = useState('');
  const [viewPassword, setViewPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showViewPassword, setShowViewPassword] = useState(false);
  const [decryptedSecret, setDecryptedSecret] = useState('');
  const [isBurned, setIsBurned] = useState(false);
  const [remainingViews, setRemainingViews] = useState<number | null>(null);
  const [showInfo, setShowInfo] = useState(false);
  const qrCodeRef = React.useRef<HTMLDivElement>(null);

  /**
   * THEME INITIALIZATION
   * Force dark mode for a consistent, professional look.
   * Note: Security headers like CSP and HSTS are enforced server-side for maximum protection.
   */
  useEffect(() => {
    document.documentElement.classList.add('dark');
  }, []);

  /**
   * ROUTING & LINK HANDLING
   * We use the window location to determine if the user is creating a secret
   * or viewing one via a shared link.
   * 
   * SECURITY NOTE: The decryption key is extracted from the URL fragment (#),
   * which is never sent to the server.
   */
  useEffect(() => {
    const processLocation = () => {
      try {
        const path = window.location.pathname;
        const hash = window.location.hash;
        
        if (path.includes('/s/')) {
          // More robust ID extraction: handle trailing slashes and potential sub-paths
          const parts = path.split('/s/');
          const id = parts[1]?.split('/')[0];
          const key = hash.replace('#', '');
          
          if (id && key) {
            setViewId(id);
            setViewKey(key);
            fetchSecret(id);
          } else if (id && !key) {
            setError('The link is incomplete – the decryption key is missing (the part after the #). Make sure you copied the entire address.');
            setView('error');
          } else {
            setError('Invalid link format.');
            setView('error');
          }
        } else if (path === '/' || path === '') {
          setView('create');
        }
      } catch {
        // Fallback to create view if location is restricted
        setView('create');
      }
    };

    processLocation();
    window.addEventListener('popstate', processLocation);
    return () => window.removeEventListener('popstate', processLocation);
  }, []);

  const fetchSecret = async (id: string) => {
    /**
     * FETCH SECRET METADATA
     * Retrieves the encrypted blob and salt from the server.
     * Does NOT retrieve the decryption key.
     */
    setLoading(true);
    try {
      const res = await fetch(`/api/secrets/${id}`);
      if (!res.ok) {
        if (res.status === 429) {
          const retryAfter = res.headers.get('Retry-After');
          const waitMsg = retryAfter ? ` Please wait ${Math.ceil(Number.parseInt(retryAfter, 10) / 60)} minute(s).` : ' Please wait a moment.';
          throw new Error('Too many requests.' + waitMsg);
        }
        const data = await res.json();
        throw new Error(data.error || 'Failed to fetch secret');
      }
      const data = await res.json();
      setViewEncryptedData(data.encryptedData);
      setViewHasPassword(data.hasPassword);
      setViewSalt(data.salt || '');
      setView('view');
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unknown error occurred');
      }
      setView('error');
    } finally {
      setLoading(false);
    }
  };

  const performSecretGeneration = async () => {
    const { encryptedData, key, salt } = await encryptSecret(secret, password);
    const pHash = (password && salt) ? await hashPassword(password, salt) : null;
    
    const res = await fetch('/api/secrets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        encryptedData,
        passwordHash: pHash,
        salt: salt,
        expirationHours: Number.parseInt(expiration, 10),
        viewLimit: Number.parseInt(viewLimit, 10)
      })
    });
    
    validateGenerateResponse(res);
    
    const { id } = await res.json();
    return `${getAppOrigin()}/s/${id}#${key}`;
  };

  const handleGenerate = async () => {
    /**
     * SECRET CREATION FLOW
     * 1. Encrypt data locally using Web Crypto API (AES-GCM).
     * 2. The encryption key is generated locally and NEVER sent to the server.
     * 3. Send only the encrypted blob (ciphertext) to the server.
     * 4. Construct a link containing the ID and the decryption key (in the # fragment).
     *    The fragment is not sent to the server in HTTP requests.
     */
    if (!secret.trim()) return;
    setLoading(true);
    setError('');
    
    try {
      const link = await performSecretGeneration();
      setGeneratedLink(link);
      setView('success');
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unknown error occurred');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    /**
     * DECRYPTION & BURNING FLOW
     * 1. Decrypt the blob locally using the key from the URL fragment.
     * 2. This happens entirely in the browser. The server never sees the plaintext.
     * 3. After successful decryption, notify the server to "burn" the secret (increment view count).
     */
    setError('');
    try {
      const decrypted = await decryptSecret(viewEncryptedData, viewKey, viewPassword, viewSalt);
      const pHash = (viewPassword && viewSalt) ? await hashPassword(viewPassword, viewSalt) : null;
      
      // Burn the secret (increment view count)
      const res = await fetch(`/api/secrets/${viewId}/burn`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passwordHash: pHash })
      });

      if (!res.ok) {
        if (res.status === 429) {
          const retryAfter = res.headers.get('Retry-After');
          const waitMsg = retryAfter ? ` Please wait ${Math.ceil(Number.parseInt(retryAfter, 10) / 60)} minute(s).` : ' Please wait a moment.';
          throw new Error('Too many attempts.' + waitMsg);
        }
        const data = await res.json();
        throw new Error(data.error || 'Failed to verify');
      }

      const data = await res.json();
      setIsBurned(data.burned);
      setRemainingViews(data.remaining);
      setDecryptedSecret(decrypted);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message || 'Invalid password or corrupted data.');
      } else {
        setError('Invalid password or corrupted data.');
      }
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } else {
        throw new Error("Clipboard API not available");
      }
    } catch (err) {
      console.error("Failed to copy:", err);
      // Fallback for insecure contexts or restricted iframes
      // SECURITY NOTE: We use a hidden textarea to perform the copy operation.
      // We set .value which is safe from XSS as it does not parse HTML.
      const textArea = document.createElement("textarea");
      textArea.style.position = "fixed";
      textArea.style.left = "-9999px";
      textArea.style.top = "0";
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        document.execCommand('copy');
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch {
        setError("Could not copy to clipboard. Please select and copy manually.");
      }
      textArea.remove();
    }
  };

  const reset = () => {
    // pushState is disabled to prevent "The operation is insecure" errors in restricted iframes
    setView('create');
    setSecret('');
    setPassword('');
    setGeneratedLink('');
    setDecryptedSecret('');
    setError('');
    setShowPassword(false);
    setShowViewPassword(false);
    setShowQR(false);
  };

  const handleDownloadQR = () => {
    try {
      if (qrCodeRef.current) {
        const svgElement = qrCodeRef.current.querySelector('svg');
        if (svgElement) {
          const svgData = new XMLSerializer().serializeToString(svgElement);
          const blob = new Blob([svgData], { type: 'image/svg+xml' });
          const url = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.download = 'SecureShare-QR.svg';
          document.body.appendChild(link);
          link.click();
          link.remove();
          URL.revokeObjectURL(url);
        }
      }
    } catch {
      setError("Could not download QR code due to browser security restrictions.");
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-4 bg-slate-950 transition-colors duration-300">
      <header className="mb-8 md:mb-12 text-center pt-4">
        <div className="flex items-center justify-center gap-3 mb-3">
          <div className="p-2 bg-indigo-600 rounded-xl md:rounded-2xl shadow-indigo-900/20 shadow-xl">
            <Shield className="w-6 h-6 md:w-8 md:h-8 text-white" />
          </div>
          <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-white">SecureShare</h1>
        </div>
        <p className="text-slate-400 max-w-xs md:max-w-md font-semibold text-base md:text-lg mx-auto">
          Share sensitive data securely. End-to-end encrypted. One-time links.
        </p>
        <div className="mt-4 flex flex-wrap justify-center gap-2">
          <span className="px-2 py-1 bg-emerald-900/20 text-emerald-400 text-[9px] md:text-[10px] font-bold uppercase tracking-widest rounded-full border border-emerald-900/30">
            Brute-Force Protected
          </span>
          <span className="px-2 py-1 bg-indigo-900/20 text-indigo-400 text-[9px] md:text-[10px] font-bold uppercase tracking-widest rounded-full border border-indigo-900/30">
            Rate Limited
          </span>
          <span className="px-2 py-1 bg-blue-900/20 text-blue-400 text-[9px] md:text-[10px] font-bold uppercase tracking-widest rounded-full border border-blue-900/30">
            E2E Encrypted
          </span>
        </div>
      </header>

      <main className="w-full max-w-xl">
        <AnimatePresence mode="wait">
          {view === 'create' && (
            <motion.div
              key="create"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="glass rounded-[2rem] p-8 md:p-10 border border-slate-200/50 dark:border-slate-800"
            >
              <div className="space-y-8">
                <div>
                  <label htmlFor="secret-input" className="block text-sm font-bold text-slate-800 dark:text-slate-200 mb-2.5 ml-1">Your Secret</label>
                  <textarea
                    id="secret-input"
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                    placeholder="Paste your password, API token, or message here..."
                    className="w-full h-40 p-5 rounded-2xl border border-slate-200 dark:border-slate-800 focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all resize-none bg-white/50 dark:bg-slate-800/50 dark:text-white placeholder:text-slate-400 text-lg"
                  />
                  <div className="flex justify-between mt-2 px-1 items-center">
                    <p className={cn(
                      "text-[10px] font-bold uppercase tracking-wider transition-colors",
                      secret.length > 750000 ? "text-amber-500" : "text-slate-400 dark:text-slate-500"
                    )}>
                      {secret.length > 750000 ? "Approaching size limit (Max ~750KB plaintext)" : "Encrypted size limit: 1MB"}
                    </p>
                    <span className={cn(
                      "text-xs font-medium transition-colors",
                      secret.length > 750000 ? "text-amber-500 font-bold" : "text-slate-400 dark:text-slate-500"
                    )}>
                      {secret.length.toLocaleString()} characters
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label htmlFor="expiration-select" className="block text-sm font-bold text-slate-800 dark:text-slate-200 mb-2.5 ml-1 flex items-center gap-2">
                      <Clock className="w-4 h-4 text-indigo-500" /> Expiration
                    </label>
                    <div className="relative">
                      <select
                        id="expiration-select"
                        value={expiration}
                        onChange={(e) => setExpiration(e.target.value)}
                        className="w-full p-3.5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-slate-800/50 dark:text-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 appearance-none cursor-pointer font-medium"
                      >
                        <option value="1">1 Hour</option>
                        <option value="24">24 Hours</option>
                        <option value="168">7 Days</option>
                      </select>
                      <div className="absolute right-4 top-1/2 -translate-y-1/2 pointer-events-none text-slate-400">
                        <ChevronRight className="w-4 h-4 rotate-90" />
                      </div>
                    </div>
                  </div>
                  <div>
                    <label htmlFor="view-limit-select" className="block text-sm font-bold text-slate-800 dark:text-slate-200 mb-2.5 ml-1 flex items-center gap-2">
                      <Eye className="w-4 h-4 text-indigo-500" /> View Limit
                    </label>
                    <div className="relative">
                      <select
                        id="view-limit-select"
                        value={viewLimit}
                        onChange={(e) => setViewLimit(e.target.value)}
                        className="w-full p-3.5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-slate-800/50 dark:text-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 appearance-none cursor-pointer font-medium"
                      >
                        <option value="1">1 View</option>
                        <option value="2">2 Views</option>
                        <option value="3">3 Views</option>
                      </select>
                      <div className="absolute right-4 top-1/2 -translate-y-1/2 pointer-events-none text-slate-400">
                        <ChevronRight className="w-4 h-4 rotate-90" />
                      </div>
                    </div>
                  </div>
                </div>

                <div>
                  <label htmlFor="password-input" className="block text-sm font-bold text-slate-800 dark:text-slate-200 mb-2.5 ml-1 flex items-center gap-2">
                    <Lock className="w-4 h-4 text-indigo-500" /> Access Password (Optional)
                  </label>
                  <div className="relative">
                    <input
                      id="password-input"
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Set a password for the recipient..."
                      className="w-full p-3.5 pr-12 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-slate-800/50 dark:text-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 font-medium"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-indigo-500 transition-colors"
                    >
                      {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                  {password && (
                    <div className="mt-3 space-y-2">
                      <div className="flex gap-1.5 h-1.5">
                        {[1, 2, 3, 4].map((level) => {
                          const strength = getPasswordStrength(password);
                          return (
                            <div
                              key={level}
                              className={cn(
                                "flex-1 rounded-full transition-all duration-500",
                                getPasswordStrengthColor(strength, level)
                              )}
                            />
                          );
                        })}
                      </div>
                      <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 ml-1">
                        Strength: {getPasswordStrengthLabel(getPasswordStrength(password))}
                      </p>
                    </div>
                  )}
                </div>

                <button
                  onClick={handleGenerate}
                  disabled={loading || !secret.trim()}
                  className="w-full py-4.5 bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-lg rounded-2xl shadow-2xl shadow-indigo-200 dark:shadow-indigo-900/20 transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed hover:scale-[1.02] active:scale-[0.98]"
                >
                  {loading ? <RefreshCw className="w-6 h-6 animate-spin" /> : <LinkIcon className="w-6 h-6" />}
                  Generate Secure Link
                </button>
              </div>
            </motion.div>
          )}

          {view === 'success' && (
            <motion.div
              key="success"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="glass rounded-3xl p-6 md:p-8 text-center border border-slate-200/60 dark:border-slate-800"
            >
              <div className="w-20 h-20 bg-emerald-100 dark:bg-emerald-900/30 rounded-full flex items-center justify-center mx-auto mb-6 shadow-inner">
                <Check className="w-10 h-10 text-emerald-600 dark:text-emerald-400" />
              </div>
              <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">Link Ready!</h2>
              <p className="text-slate-500 dark:text-slate-400 mb-8 font-medium">
                Your secret is encrypted. Share the link below.
              </p>

              <div className="relative mb-8">
                <input
                  readOnly
                  value={generatedLink}
                  className="w-full p-4 pr-14 rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 dark:text-white font-mono text-sm shadow-inner"
                />
                <button
                  onClick={() => copyToClipboard(generatedLink)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 p-2.5 hover:bg-indigo-100 dark:hover:bg-indigo-900/50 text-indigo-600 dark:text-indigo-400 rounded-xl transition-all"
                >
                  {copied ? <Check className="w-5 h-5" /> : <Copy className="w-5 h-5" />}
                </button>
              </div>

              <div className="mb-8 flex flex-col items-center">
                <button
                  onClick={() => setShowQR(!showQR)}
                  className="text-xs font-bold uppercase tracking-widest text-slate-400 hover:text-indigo-500 transition-colors flex items-center gap-2 mb-4"
                >
                  {showQR ? 'Hide QR Code' : 'Show QR Code'}
                </button>
                
                <AnimatePresence>
                  {showQR && (
                    <motion.div
                      initial={{ opacity: 0, height: 0, scale: 0.9 }}
                      animate={{ opacity: 1, height: 'auto', scale: 1 }}
                      exit={{ opacity: 0, height: 0, scale: 0.9 }}
                      className="overflow-hidden bg-white p-4 rounded-2xl shadow-xl border border-slate-100"
                      ref={qrCodeRef}
                    >
                      <QRCodeSVG 
                        value={generatedLink} 
                        size={180}
                        level="H"
                        includeMargin={false}
                      />
                    </motion.div>
                  )}
                </AnimatePresence>

                {showQR && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
                    <button 
                      onClick={handleDownloadQR}
                      className="mt-4 text-xs font-bold text-indigo-400 hover:text-indigo-300 transition-colors"
                    >
                      Download QR (SVG)
                    </button>
                  </motion.div>
                )}
              </div>

              <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-100 dark:border-blue-900/30 rounded-2xl p-5 text-left mb-8 shadow-sm space-y-4">
                <div className="flex gap-4">
                  <Info className="w-6 h-6 text-blue-600 dark:text-blue-500 shrink-0" />
                  <div>
                    <p className="text-sm font-bold text-blue-900 dark:text-blue-200">Safe for Messaging Apps</p>
                    <p className="text-sm text-blue-800 dark:text-blue-300 leading-relaxed mt-1">
                      Link previews (Teams, Slack bots) <strong>will not</strong> burn your secret. The secret is only accessed when you explicitly click "Decrypt".
                    </p>
                  </div>
                </div>
                <div className="flex gap-4">
                  <Shield className="w-6 h-6 text-blue-600 dark:text-blue-500 shrink-0" />
                  <div>
                    <p className="text-sm font-bold text-blue-900 dark:text-blue-200">Best Practice</p>
                    <p className="text-sm text-blue-800 dark:text-blue-300 leading-relaxed mt-1">
                      Send the link and the password via separate channels (e.g. Teams + SMS) for maximum security.
                    </p>
                  </div>
                </div>
              </div>

              <button
                onClick={reset}
                className="text-indigo-600 dark:text-indigo-400 font-bold hover:underline flex items-center gap-1 mx-auto transition-all"
              >
                Create another secret <ChevronRight className="w-4 h-4" />
              </button>
            </motion.div>
          )}

          {view === 'view' && (
            <motion.div
              key="view"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass rounded-3xl p-6 md:p-8 border border-slate-200/60 dark:border-slate-800"
            >
              {!decryptedSecret ? (
                <div className="text-center">
                  <div className="w-20 h-20 bg-indigo-100 dark:bg-indigo-900/30 rounded-full flex items-center justify-center mx-auto mb-6 shadow-inner">
                    <Lock className="w-10 h-10 text-indigo-600 dark:text-indigo-400" />
                  </div>
                  <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">Secret Received</h2>
                  <p className="text-slate-500 dark:text-slate-400 mb-8 font-medium">
                    This secret is encrypted. {viewHasPassword ? 'Enter the password to decrypt it.' : 'Click the button below to view it.'}
                  </p>

                  {viewHasPassword && (
                    <>
                      <div className="mb-6 relative">
                        <label htmlFor="view-password-input" className="sr-only">Access password</label>
                        <input
                          id="view-password-input"
                          type={showViewPassword ? "text" : "password"}
                          value={viewPassword}
                          onChange={(e) => setViewPassword(e.target.value)}
                          placeholder="Access password..."
                          className="w-full p-4 pr-14 rounded-2xl border border-slate-200 dark:border-slate-800 focus:ring-2 focus:ring-indigo-500 bg-white/50 dark:bg-slate-900/50 dark:text-white text-center text-lg"
                        />
                        <button
                          type="button"
                          onClick={() => setShowViewPassword(!showViewPassword)}
                          className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-indigo-500 transition-colors"
                        >
                          {showViewPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                        </button>
                      </div>
                      <div className="mb-6 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-100 dark:border-amber-900/30 rounded-xl flex items-center gap-3">
                        <AlertCircle className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0" />
                        <p className="text-xs text-amber-800 dark:text-amber-300 font-semibold text-left">
                          Security Policy: This secret will be permanently deleted after 3 failed password attempts.
                        </p>
                      </div>
                    </>
                  )}

                  {error && <p className="text-red-500 font-semibold text-sm mb-6">{error}</p>}

                  <button
                    onClick={handleDecrypt}
                    className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-2xl shadow-xl transition-all hover:scale-[1.02] active:scale-[0.98]"
                  >
                    Decrypt and View
                  </button>
                </div>
              ) : (
                <div>
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-2xl font-bold text-slate-900 dark:text-white">Secret Content</h2>
                    <button
                      onClick={() => copyToClipboard(decryptedSecret)}
                      className="flex items-center gap-2 px-4 py-2 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 rounded-xl hover:bg-indigo-100 dark:hover:bg-indigo-900/50 transition-all font-bold"
                    >
                      {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-slate-100 p-6 rounded-2xl font-mono text-sm break-all whitespace-pre-wrap mb-8 max-h-96 overflow-y-auto border border-slate-200 dark:border-slate-800 shadow-inner">
                    {decryptedSecret}
                  </div>
                  
                  {isBurned ? (
                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-100 dark:border-red-900/30 rounded-2xl p-5 flex gap-4 shadow-sm">
                      <Trash2 className="w-6 h-6 text-red-600 dark:text-red-400 shrink-0" />
                      <p className="text-sm text-red-800 dark:text-red-300 font-medium leading-relaxed">
                        This secret has been deleted from the server. It will no longer be accessible after you close or refresh this page.
                      </p>
                    </div>
                  ) : (
                    <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-100 dark:border-blue-900/30 rounded-2xl p-5 flex gap-4 shadow-sm">
                      <Eye className="w-6 h-6 text-blue-600 dark:text-blue-400 shrink-0" />
                      <div>
                        <p className="text-sm text-blue-800 dark:text-blue-300 font-bold">Secret still available</p>
                        <p className="text-sm text-blue-700 dark:text-blue-400 font-medium leading-relaxed">
                          This secret can be viewed {remainingViews} more {remainingViews === 1 ? 'time' : 'times'} before it is deleted.
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          )}

          {view === 'error' && (
            <motion.div
              key="error"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="glass rounded-3xl p-6 md:p-8 text-center border border-slate-200/60 dark:border-slate-800"
            >
              <div className="w-20 h-20 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center mx-auto mb-6 shadow-inner">
                <ShieldAlert className="w-10 h-10 text-red-600 dark:text-red-400" />
              </div>
              <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">Link Invalid</h2>
              <p className="text-slate-500 dark:text-slate-400 mb-10 font-medium">
                {error || 'This secret has expired or has already been opened and deleted from the server.'}
              </p>
              <button
                onClick={reset}
                className="w-full py-4 bg-slate-900 dark:bg-slate-800 text-white font-bold rounded-2xl hover:bg-slate-800 dark:hover:bg-slate-700 transition-all shadow-lg"
              >
                Back to Home
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className="mt-auto py-8 text-slate-400 dark:text-slate-500 text-sm flex flex-col items-center gap-4">
        <button 
          onClick={() => setShowInfo(true)}
          className="flex items-center gap-2 hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors font-medium"
        >
          <Info className="w-4 h-4" /> More Information
        </button>
        <p>&copy; 2026 SecureShare.</p>
      </footer>

      <AnimatePresence>
        {showInfo && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 dark:bg-black/60 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl max-w-lg w-full overflow-hidden border dark:border-slate-800"
            >
              <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
                <h3 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-indigo-600 dark:text-indigo-400" /> How it works
                </h3>
                <button onClick={() => setShowInfo(false)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full transition-colors">
                  <X className="w-5 h-5 text-slate-400 dark:text-slate-500" />
                </button>
              </div>
              <div className="p-6 space-y-4 text-slate-600 dark:text-slate-400">
                <section>
                  <h4 className="font-semibold text-slate-900 dark:text-white mb-1">End-to-End Encryption</h4>
                  <p className="text-sm">
                    Your data is encrypted in your browser before being sent to the server. The decryption key is part of the URL fragment (#), which is never sent to our servers.
                  </p>
                </section>
                <section>
                  <h4 className="font-semibold text-slate-900 dark:text-white mb-1">Zero-Knowledge Storage</h4>
                  <p className="text-sm">
                    We only store encrypted blobs. Without the unique link key, even we cannot read your secrets.
                  </p>
                </section>
                <section>
                  <h4 className="font-semibold text-slate-900 dark:text-white mb-1">Advanced Protection</h4>
                  <p className="text-sm">
                    Strict Content Security Policy (CSP) prevents XSS attacks, while HSTS forces secure connections. Brute-force protection automatically deletes secrets after 3 failed password attempts.
                  </p>
                </section>
                <section>
                  <h4 className="font-semibold text-slate-900 dark:text-white mb-1">Automatic Destruction</h4>
                  <p className="text-sm">
                    Secrets are automatically deleted after the view limit is reached or the expiration time passes. Once deleted, they are gone forever.
                  </p>
                </section>
              </div>
              <div className="p-6 bg-slate-50 dark:bg-slate-900/50 text-center border-t dark:border-slate-800">
                <button 
                  onClick={() => setShowInfo(false)}
                  className="px-6 py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 transition-colors"
                >
                  Got it
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
