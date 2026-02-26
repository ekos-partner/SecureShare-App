import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  Key, 
  Trash2, 
  Plus, 
  BarChart3, 
  Clock, 
  LogOut, 
  Check, 
  Copy,
  AlertCircle,
  Activity,
  Server,
  Users,
  FileText,
  Lock,
  Smartphone,
  UserPlus
} from 'lucide-react';

function cn(...classes: (string | boolean | undefined)[]) {
  return classes.filter(Boolean).join(' ');
}

interface Stats {
  totalSecrets: number;
  activeKeys: number;
  totalViews: number;
  uptime: number;
}

interface ApiKey {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
  usage_count: number;
}

interface User {
  id: string;
  username: string;
  is_root: boolean;
  must_change_password: boolean;
  is_totp_enabled: boolean;
  created_at: string;
}

interface AuditLog {
  id: string;
  timestamp: string;
  action: string;
  username: string | null;
  ip_address: string;
  details: string;
}

export default function AdminDashboard() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpToken, setTotpToken] = useState('');
  const [requiresTotp, setRequiresTotp] = useState(false);
  const [mustChangePassword, setMustChangePassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [uptimeSeconds, setUptimeSeconds] = useState<number>(0);
  const [newKeyName, setNewKeyName] = useState('');
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'stats' | 'keys' | 'users' | 'logs' | 'security'>('stats');
  
  // User Management
  const [newUserName, setNewUserName] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  
  // Security / TOTP
  const [totpSetupData, setTotpSetupData] = useState<{ qrCodeUrl: string, secret: string } | null>(null);
  const [totpVerifyToken, setTotpVerifyToken] = useState('');
  const [newAdminPassword, setNewAdminPassword] = useState('');
  const [passwordChangeSuccess, setPasswordChangeSuccess] = useState(false);

  useEffect(() => {
    if (isLoggedIn) {
      fetchStats();
      fetchKeys();
      fetchUsers();
      fetchLogs();
    }
  }, [isLoggedIn]);

  useEffect(() => {
    if (!isLoggedIn) return;
    const interval = setInterval(() => {
      setUptimeSeconds(prev => prev > 0 ? prev + 1 : 0);
    }, 1000);
    return () => clearInterval(interval);
  }, [isLoggedIn]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, totpToken })
      });
      const data = await res.json();
      
      if (res.ok) {
        if (data.requiresTotp) {
          setRequiresTotp(true);
        } else {
          setIsLoggedIn(true);
          setMustChangePassword(data.mustChangePassword);
          if (data.mustChangePassword) {
            setActiveTab('security');
          }
        }
      } else {
        setError(data.error || 'Login failed');
      }
    } catch {
      setError('Connection error');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await fetch('/api/admin/logout', { method: 'POST' });
    setIsLoggedIn(false);
    setRequiresTotp(false);
    setTotpToken('');
    setPassword('');
    setStats(null);
    setKeys([]);
    setUsers([]);
    setLogs([]);
  };

  const fetchStats = async () => {
    const res = await fetch('/api/admin/stats');
    if (res.ok) {
      const data = await res.json();
      setStats(data);
      setUptimeSeconds(data.uptime);
    }
  };

  const fetchKeys = async () => {
    const res = await fetch('/api/admin/keys');
    if (res.ok) setKeys(await res.json());
  };

  const fetchUsers = async () => {
    const res = await fetch('/api/admin/users');
    if (res.ok) setUsers(await res.json());
  };

  const fetchLogs = async () => {
    const res = await fetch('/api/admin/logs');
    if (res.ok) setLogs(await res.json());
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: newUserName.trim(), password: newUserPassword })
      });
      if (res.ok) {
        setNewUserName('');
        setNewUserPassword('');
        fetchUsers();
        fetchLogs();
      } else {
        const data = await res.json();
        setError(data.error);
      }
    } catch {
      setError('Failed to create user');
    }
  };

  const handleDeleteUser = async (id: string) => {
    if (!confirm('Are you sure you want to delete this user?')) return;
    const res = await fetch(`/api/admin/users/${id}`, { method: 'DELETE' });
    if (res.ok) {
      fetchUsers();
      fetchLogs();
    } else {
      const data = await res.json();
      alert(data.error);
    }
  };

  const handleSetupTotp = async () => {
    setError('');
    try {
      const res = await fetch('/api/admin/totp/setup', { method: 'POST' });
      if (res.ok) {
        setTotpSetupData(await res.json());
      } else {
        const data = await res.json();
        setError(data.error || 'Failed to setup 2FA');
      }
    } catch (err) {
      setError('Connection error or server unreachable');
      console.error('2FA setup error:', err);
    }
  };

  const handleVerifyTotp = async () => {
    const res = await fetch('/api/admin/totp/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: totpVerifyToken })
    });
    if (res.ok) {
      setTotpSetupData(null);
      setTotpVerifyToken('');
      fetchUsers(); // Refresh to show 2FA enabled
      fetchLogs();
    } else {
      const data = await res.json();
      setError(data.error);
    }
  };

  const handleDisableTotp = async () => {
    if (!confirm('Are you sure you want to disable 2FA?')) return;
    const res = await fetch('/api/admin/totp/disable', { method: 'POST' });
    if (res.ok) {
      fetchUsers();
      fetchLogs();
    }
  };

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName) return;
    try {
      const res = await fetch('/api/admin/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName })
      });
      if (res.ok) {
        const data = await res.json();
        setGeneratedKey(data.apiKey);
        setNewKeyName('');
        fetchKeys();
        fetchStats();
      }
    } catch {
      setError('Failed to create key');
    }
  };

  const handleDeleteKey = async (id: string) => {
    if (!confirm('Are you sure you want to delete this API key?')) return;
    const res = await fetch(`/api/admin/keys/${id}`, { method: 'DELETE' });
    if (res.ok) {
      fetchKeys();
      fetchStats();
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setPasswordChangeSuccess(false);
    try {
      const res = await fetch('/api/admin/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ newPassword: newAdminPassword })
      });
      if (res.ok) {
        setPasswordChangeSuccess(true);
        setNewAdminPassword('');
      } else {
        const data = await res.json();
        setError(data.error || 'Failed to change password');
      }
    } catch {
      setError('Connection error');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const formatUptime = (seconds: number) => {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${d}d ${h}h ${m}m`;
  };

  if (!isLoggedIn) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-slate-950">
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="w-full max-w-md glass p-8 rounded-[2rem] border border-slate-800"
        >
          <div className="flex items-center gap-3 mb-8 justify-center">
            <div className="p-2 bg-indigo-600 rounded-xl">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-white">Admin Access</h1>
          </div>

          <form onSubmit={handleLogin} className="space-y-6">
            {!requiresTotp ? (
              <>
                <div>
                  <label className="block text-sm font-bold text-slate-400 mb-2 ml-1">Username</label>
                  <input 
                    type="text" 
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full p-4 rounded-2xl border border-slate-800 bg-slate-900/50 text-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all"
                    placeholder="admin"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-bold text-slate-400 mb-2 ml-1">Password</label>
                  <input 
                    type="password" 
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full p-4 rounded-2xl border border-slate-800 bg-slate-900/50 text-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all"
                    placeholder="••••••••"
                    required
                  />
                </div>
              </>
            ) : (
              <div>
                <label className="block text-sm font-bold text-slate-400 mb-2 ml-1">2FA Code</label>
                <input 
                  type="text" 
                  value={totpToken}
                  onChange={(e) => setTotpToken(e.target.value)}
                  className="w-full p-4 rounded-2xl border border-slate-800 bg-slate-900/50 text-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all text-center text-2xl tracking-[1em] font-mono"
                  placeholder="000000"
                  maxLength={6}
                  autoFocus
                  required
                />
                <p className="mt-2 text-center text-xs text-slate-500">Enter the 6-digit code from your authenticator app</p>
              </div>
            )}

            {error && (
              <div className="p-4 bg-red-900/20 border border-red-900/30 rounded-xl flex items-center gap-3">
                <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
                <p className="text-sm text-red-400 font-medium">{error}</p>
              </div>
            )}

            <button 
              type="submit"
              disabled={loading}
              className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-2xl transition-all disabled:opacity-50"
            >
              {loading ? 'Authenticating...' : 'Login to Dashboard'}
            </button>
          </form>
          
          <p className="mt-6 text-center text-xs text-slate-500">
            SecureShare v1.1.0 Admin Panel
          </p>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-4 md:p-8">
      <div className="max-w-6xl mx-auto">
        <header className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-12">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-indigo-600 rounded-2xl">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">Admin Dashboard</h1>
              <p className="text-slate-400 font-medium">System Management & API Control</p>
            </div>
          </div>
          <button 
            onClick={handleLogout}
            className="flex items-center gap-2 px-6 py-3 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-2xl transition-all font-bold border border-slate-800"
          >
            <LogOut className="w-5 h-5" /> Logout
          </button>
        </header>

        {/* Tabs Navigation */}
        <div className="flex gap-2 mb-8 border-b border-slate-800 pb-4 overflow-x-auto no-scrollbar">
          <TabButton active={activeTab === 'stats'} onClick={() => setActiveTab('stats')} icon={<BarChart3 className="w-4 h-4" />} label="Overview" />
          <TabButton active={activeTab === 'keys'} onClick={() => setActiveTab('keys')} icon={<Key className="w-4 h-4" />} label="API Keys" />
          <TabButton active={activeTab === 'users'} onClick={() => setActiveTab('users')} icon={<Users className="w-4 h-4" />} label="Users" />
          <TabButton active={activeTab === 'logs'} onClick={() => setActiveTab('logs')} icon={<FileText className="w-4 h-4" />} label="Audit Logs" />
          <TabButton active={activeTab === 'security'} onClick={() => setActiveTab('security')} icon={<Lock className="w-4 h-4" />} label="Security" />
        </div>

        <AnimatePresence mode="wait">
          {activeTab === 'stats' && (
            <motion.div
              key="stats"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                <StatCard 
                  icon={<Key className="w-6 h-6 text-indigo-400" />} 
                  label="Active Secrets" 
                  value={stats?.totalSecrets || 0} 
                />
                <StatCard 
                  icon={<Activity className="w-6 h-6 text-emerald-400" />} 
                  label="Total Views" 
                  value={stats?.totalViews || 0} 
                />
                <StatCard 
                  icon={<Server className="w-6 h-6 text-amber-400" />} 
                  label="API Keys" 
                  value={stats?.activeKeys || 0} 
                />
                <StatCard 
                  icon={<Clock className="w-6 h-6 text-blue-400" />} 
                  label="Uptime" 
                  value={formatUptime(uptimeSeconds)} 
                />
              </div>
            </motion.div>
          )}

          {activeTab === 'keys' && (
            <motion.div
              key="keys"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="grid grid-cols-1 lg:grid-cols-3 gap-8"
            >
              {/* API Keys Management */}
              <div className="lg:col-span-2 space-y-6">
                <div className="glass rounded-[2rem] border border-slate-800 overflow-hidden">
                  <div className="p-6 border-b border-slate-800 flex items-center justify-between">
                    <h2 className="text-xl font-bold text-white flex items-center gap-2">
                      <Key className="w-5 h-5 text-indigo-400" /> API Keys
                    </h2>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left">
                      <thead>
                        <tr className="text-xs font-bold uppercase tracking-wider text-slate-500 border-b border-slate-800">
                          <th className="px-6 py-4">Name</th>
                          <th className="px-6 py-4">Usage</th>
                          <th className="px-6 py-4">Last Used</th>
                          <th className="px-6 py-4 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                        {keys.length === 0 ? (
                          <tr>
                            <td colSpan={4} className="px-6 py-12 text-center text-slate-500 italic">
                              No API keys generated yet.
                            </td>
                          </tr>
                        ) : (
                          keys.map((key) => (
                            <tr key={key.id} className="hover:bg-slate-900/30 transition-colors">
                              <td className="px-6 py-4">
                                <div className="font-bold text-white">{key.name}</div>
                                <div className="text-[10px] font-mono text-slate-500">ID: {key.id}</div>
                              </td>
                              <td className="px-6 py-4">
                                <span className="px-2 py-1 bg-indigo-900/20 text-indigo-400 text-[10px] font-bold rounded-full border border-indigo-900/30">
                                  {key.usage_count} calls
                                </span>
                              </td>
                              <td className="px-6 py-4 text-sm text-slate-400">
                                {key.last_used_at ? new Date(key.last_used_at).toLocaleString() : 'Never'}
                              </td>
                              <td className="px-6 py-4 text-right">
                                <button 
                                  onClick={() => handleDeleteKey(key.id)}
                                  className="p-2 text-slate-500 hover:text-red-400 transition-colors"
                                >
                                  <Trash2 className="w-5 h-5" />
                                </button>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Create Key Form */}
              <div className="space-y-6">
                <div className="glass rounded-[2rem] p-6 border border-slate-800">
                  <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
                    <Plus className="w-5 h-5 text-indigo-400" /> Create API Key
                  </h2>
                  <form onSubmit={handleCreateKey} className="space-y-4">
                    <div>
                      <label className="block text-sm font-bold text-slate-400 mb-2 ml-1">Key Name</label>
                      <input 
                        type="text" 
                        value={newKeyName}
                        onChange={(e) => setNewKeyName(e.target.value)}
                        className="w-full p-3.5 rounded-2xl border border-slate-800 bg-slate-900/50 text-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all"
                        placeholder="e.g. HR System"
                        required
                      />
                    </div>
                    <button 
                      type="submit"
                      className="w-full py-3.5 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-2xl transition-all shadow-lg shadow-indigo-900/20"
                    >
                      Generate New Key
                    </button>
                  </form>

                  <AnimatePresence>
                    {generatedKey && (
                      <motion.div 
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="mt-6 p-4 bg-emerald-900/20 border border-emerald-900/30 rounded-2xl"
                      >
                        <p className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2">New API Key Generated</p>
                        <p className="text-[10px] text-emerald-300/70 mb-3 leading-relaxed">
                          Copy this key now. It will <strong>never</strong> be shown again for security reasons.
                        </p>
                        <div className="relative">
                          <input 
                            readOnly 
                            value={generatedKey}
                            className="w-full p-3 pr-12 bg-slate-950 border border-emerald-900/30 rounded-xl text-xs font-mono text-emerald-400"
                          />
                          <button 
                            onClick={() => copyToClipboard(generatedKey)}
                            className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-emerald-400 hover:bg-emerald-900/30 rounded-lg transition-all"
                          >
                            {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                          </button>
                        </div>
                        <button 
                          onClick={() => setGeneratedKey(null)}
                          className="w-full mt-4 py-2 text-xs font-bold text-slate-400 hover:text-white transition-colors"
                        >
                          I've saved it
                        </button>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'users' && (
            <motion.div
              key="users"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="grid grid-cols-1 lg:grid-cols-3 gap-8"
            >
              <div className="lg:col-span-2">
                <div className="glass rounded-[2rem] border border-slate-800 overflow-hidden">
                  <div className="p-6 border-b border-slate-800">
                    <h2 className="text-xl font-bold text-white flex items-center gap-2">
                      <Users className="w-5 h-5 text-indigo-400" /> Administrators
                    </h2>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left">
                      <thead>
                        <tr className="text-xs font-bold uppercase tracking-wider text-slate-500 border-b border-slate-800">
                          <th className="px-6 py-4">Username</th>
                          <th className="px-6 py-4">Status</th>
                          <th className="px-6 py-4">2FA</th>
                          <th className="px-6 py-4 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                        {users.map((u) => (
                          <tr key={u.id} className="hover:bg-slate-900/30 transition-colors">
                            <td className="px-6 py-4">
                              <div className="font-bold text-white flex items-center gap-2">
                                {u.username}
                                {u.is_root && <span className="text-[10px] bg-indigo-600 text-white px-1.5 py-0.5 rounded uppercase">Root</span>}
                              </div>
                              <div className="text-[10px] text-slate-500">Created: {new Date(u.created_at).toLocaleDateString()}</div>
                            </td>
                            <td className="px-6 py-4">
                              {u.must_change_password ? (
                                <span className="text-amber-400 text-xs font-bold flex items-center gap-1">
                                  <AlertCircle className="w-3 h-3" /> Password Reset Required
                                </span>
                              ) : (
                                <span className="text-emerald-400 text-xs font-bold flex items-center gap-1">
                                  <Check className="w-3 h-3" /> Active
                                </span>
                              )}
                            </td>
                            <td className="px-6 py-4">
                              {u.is_totp_enabled ? (
                                <span className="text-indigo-400 text-xs font-bold flex items-center gap-1">
                                  <Smartphone className="w-3 h-3" /> Enabled
                                </span>
                              ) : (
                                <span className="text-slate-500 text-xs font-bold">Disabled</span>
                              )}
                            </td>
                            <td className="px-6 py-4 text-right">
                              {!u.is_root && (
                                <button 
                                  onClick={() => handleDeleteUser(u.id)}
                                  className="p-2 text-slate-500 hover:text-red-400 transition-colors"
                                >
                                  <Trash2 className="w-5 h-5" />
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              <div>
                <div className="glass rounded-[2rem] p-6 border border-slate-800">
                  <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
                    <UserPlus className="w-5 h-5 text-indigo-400" /> Add Administrator
                  </h2>
                  <form onSubmit={handleCreateUser} className="space-y-4">
                    <div>
                      <label className="block text-sm font-bold text-slate-400 mb-2 ml-1">Username</label>
                      <input 
                        type="text" 
                        value={newUserName}
                        onChange={(e) => setNewUserName(e.target.value)}
                        className="w-full p-3.5 rounded-2xl border border-slate-800 bg-slate-900/50 text-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all"
                        placeholder="john_doe"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-bold text-slate-400 mb-2 ml-1">Initial Password</label>
                      <input 
                        type="password" 
                        value={newUserPassword}
                        onChange={(e) => setNewUserPassword(e.target.value)}
                        className="w-full p-3.5 rounded-2xl border border-slate-800 bg-slate-900/50 text-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all"
                        placeholder="••••••••"
                        required
                        minLength={8}
                      />
                      <p className="mt-2 text-[10px] text-slate-500 italic">User will be forced to change this password on first login.</p>
                    </div>
                    <button 
                      type="submit"
                      className="w-full py-3.5 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-2xl transition-all shadow-lg shadow-indigo-900/20"
                    >
                      Create User
                    </button>
                  </form>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'logs' && (
            <motion.div
              key="logs"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <div className="glass rounded-[2rem] border border-slate-800 overflow-hidden">
                <div className="p-6 border-b border-slate-800 flex items-center justify-between">
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    <FileText className="w-5 h-5 text-indigo-400" /> Audit Logs
                  </h2>
                  <button onClick={fetchLogs} className="text-xs font-bold text-indigo-400 hover:text-indigo-300">Refresh</button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="text-xs font-bold uppercase tracking-wider text-slate-500 border-b border-slate-800">
                        <th className="px-6 py-4">Timestamp</th>
                        <th className="px-6 py-4">Action</th>
                        <th className="px-6 py-4">User</th>
                        <th className="px-6 py-4">IP Address</th>
                        <th className="px-6 py-4">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {logs.map((log) => (
                        <tr key={log.id} className="text-sm hover:bg-slate-900/30 transition-colors">
                          <td className="px-6 py-4 text-slate-400 whitespace-nowrap">
                            {new Date(log.timestamp).toLocaleString()}
                          </td>
                          <td className="px-6 py-4">
                            <span className={cn(
                              "px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border",
                              log.action.includes('FAILED') ? "bg-red-900/20 text-red-400 border-red-900/30" :
                              log.action.includes('SUCCESS') ? "bg-emerald-900/20 text-emerald-400 border-emerald-900/30" :
                              "bg-slate-800 text-slate-300 border-slate-700"
                            )}>
                              {log.action}
                            </span>
                          </td>
                          <td className="px-6 py-4 font-medium text-white">{log.username || 'SYSTEM'}</td>
                          <td className="px-6 py-4 font-mono text-xs text-slate-500">{log.ip_address}</td>
                          <td className="px-6 py-4 text-slate-400 max-w-xs truncate">{log.details}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'security' && (
            <motion.div
              key="security"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="grid grid-cols-1 lg:grid-cols-2 gap-8"
            >
              {/* Password Management */}
              <div className="glass rounded-[2rem] p-8 border border-slate-800">
                <h2 className="text-2xl font-bold text-white mb-2 flex items-center gap-3">
                  <Lock className="w-6 h-6 text-indigo-400" /> Password Management
                </h2>
                <p className="text-slate-400 mb-8 font-medium">Update your administrative password.</p>

                {mustChangePassword && (
                  <div className="mb-6 p-4 bg-amber-900/20 border border-amber-900/30 rounded-xl flex items-center gap-3">
                    <AlertCircle className="w-5 h-5 text-amber-400 shrink-0" />
                    <p className="text-sm text-amber-400 font-bold">Security Action Required: Please change your initial password.</p>
                  </div>
                )}

                <form onSubmit={handleChangePassword} className="space-y-6">
                  <div>
                    <label className="block text-sm font-bold text-slate-400 mb-2 ml-1">New Password</label>
                    <input 
                      type="password" 
                      value={newAdminPassword}
                      onChange={(e) => setNewAdminPassword(e.target.value)}
                      className="w-full p-4 rounded-2xl border border-slate-800 bg-slate-900/50 text-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all"
                      placeholder="At least 8 characters..."
                      required
                      minLength={8}
                    />
                  </div>

                  {passwordChangeSuccess && (
                    <div className="p-4 bg-emerald-900/20 border border-emerald-900/30 rounded-xl flex items-center gap-3">
                      <Check className="w-5 h-5 text-emerald-400 shrink-0" />
                      <p className="text-sm text-emerald-400 font-medium">Password updated successfully!</p>
                    </div>
                  )}

                  <button 
                    type="submit"
                    disabled={loading}
                    className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-2xl transition-all shadow-lg shadow-indigo-900/20"
                  >
                    {loading ? 'Updating...' : 'Update Password'}
                  </button>
                </form>

                <div className="mt-12 p-6 bg-slate-900/50 border border-slate-800 rounded-2xl">
                  <h3 className="text-white font-bold mb-2 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-indigo-400" /> Brute-Force Protection
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    The system automatically locks accounts for 15 minutes after 5 failed login attempts. 
                    Failed attempts are logged with IP addresses for auditing.
                  </p>
                </div>
              </div>

              {/* 2FA Management */}
              <div className="glass rounded-[2rem] p-8 border border-slate-800">
                <h2 className="text-2xl font-bold text-white mb-2 flex items-center gap-3">
                  <Smartphone className="w-6 h-6 text-indigo-400" /> Two-Factor Authentication
                </h2>
                <p className="text-slate-400 mb-8 font-medium">Add an extra layer of security to your account.</p>

                {users.find(u => u.username === username)?.is_totp_enabled ? (
                  <div className="space-y-6">
                    <div className="p-6 bg-emerald-900/10 border border-emerald-900/20 rounded-2xl flex items-center gap-4">
                      <div className="p-3 bg-emerald-600 rounded-xl">
                        <Check className="w-6 h-6 text-white" />
                      </div>
                      <div>
                        <p className="text-emerald-400 font-bold">2FA is currently active</p>
                        <p className="text-xs text-slate-400">Your account is protected by TOTP.</p>
                      </div>
                    </div>
                    <button 
                      onClick={handleDisableTotp}
                      className="w-full py-4 bg-slate-900 hover:bg-red-900/20 hover:text-red-400 text-slate-400 font-bold rounded-2xl transition-all border border-slate-800"
                    >
                      Disable 2FA
                    </button>
                  </div>
                ) : (
                  <div className="space-y-6">
                    {!totpSetupData ? (
                      <button 
                        onClick={handleSetupTotp}
                        className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-2xl transition-all shadow-lg shadow-indigo-900/20"
                      >
                        Enable 2FA
                      </button>
                    ) : (
                      <div className="space-y-6">
                        <div className="flex justify-center p-4 bg-white rounded-2xl">
                          <img src={totpSetupData.qrCodeUrl} alt="QR Code" className="w-48 h-48" />
                        </div>
                        <div className="space-y-4">
                          <p className="text-sm text-slate-400 text-center">
                            Scan this QR code with Google Authenticator or Microsoft Authenticator, then enter the 6-digit code below.
                          </p>
                          <input 
                            type="text" 
                            value={totpVerifyToken}
                            onChange={(e) => setTotpVerifyToken(e.target.value)}
                            className="w-full p-4 rounded-2xl border border-slate-800 bg-slate-900/50 text-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all text-center text-2xl tracking-[0.5em] font-mono"
                            placeholder="000000"
                            maxLength={6}
                          />
                          <button 
                            onClick={handleVerifyTotp}
                            className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-2xl transition-all"
                          >
                            Verify & Activate
                          </button>
                          <button 
                            onClick={() => setTotpSetupData(null)}
                            className="w-full py-2 text-xs text-slate-500 hover:text-white transition-colors"
                          >
                            Cancel Setup
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                <div className="mt-12 p-6 bg-indigo-900/10 border border-indigo-900/20 rounded-2xl">
                  <h3 className="text-indigo-400 font-bold mb-2 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4" /> Standalone Recovery
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    If you lose access to your account or 2FA, use the CLI recovery tool:
                    <code className="block mt-2 p-2 bg-slate-950 rounded border border-slate-800 text-indigo-300">
                      npm run reset-admin admin new_password
                    </code>
                    This command requires direct access to the server terminal.
                  </p>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

function TabButton({ active, onClick, icon, label }: { active: boolean, onClick: () => void, icon: React.ReactNode, label: string }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-2 px-4 py-2 rounded-xl transition-all font-bold text-sm",
        active 
          ? "bg-indigo-600 text-white shadow-lg shadow-indigo-900/20" 
          : "text-slate-500 hover:text-slate-300 hover:bg-slate-900"
      )}
    >
      {icon}
      {label}
    </button>
  );
}

function StatCard({ icon, label, value }: { icon: React.ReactNode, label: string, value: string | number }) {
  return (
    <div className="glass p-6 rounded-[2rem] border border-slate-800">
      <div className="flex items-center gap-4 mb-4">
        <div className="p-2 bg-slate-900 rounded-xl border border-slate-800">
          {icon}
        </div>
        <span className="text-sm font-bold text-slate-500 uppercase tracking-wider">{label}</span>
      </div>
      <div className="text-3xl font-bold text-white">{value}</div>
    </div>
  );
}
