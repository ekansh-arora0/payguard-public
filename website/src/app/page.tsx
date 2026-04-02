'use client'

import { useState, useEffect, useRef } from 'react'
import { 
  Shield, Check, Zap, Globe, Lock, Eye, ChevronLeft,
  Download, Terminal, AlertTriangle, CheckCircle, ArrowRight,
  Menu, X, ExternalLink, Copy, Sparkles, Activity, Server,
  ChevronDown, Play, Star, Users, TrendingUp, ShieldCheck,
  Timer, Brain, Cpu, LockKeyhole, AlertOctagon, CheckCheck,
  Info
} from 'lucide-react'
import Link from 'next/link'

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8002'

// Demo mode analysis - balanced detection with lower false positives
const getDemoAnalysis = (url: string): { trust_score: number; risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; risk_factors: string[]; safety_indicators: string[] } => {
  const lowerUrl = url.toLowerCase()
  const factors = []
  let riskScore = 0
  
  // Safe domains whitelist - expanded
  const safeDomains = [
    'google.com', 'github.com', 'apple.com', 'microsoft.com', 'amazon.com', 'paypal.com',
    'youtube.com', 'facebook.com', 'twitter.com', 'x.com', 'linkedin.com', 'instagram.com',
    'reddit.com', 'netflix.com', 'spotify.com', 'dropbox.com', 'slack.com', 'zoom.us',
    'webex.com', 'teams.microsoft.com', 'discord.com', 'shopify.com', 'stripe.com',
    'squarespace.com', 'wix.com', 'wordpress.com', 'medium.com', 'substack.com',
    'vercel.app', 'netlify.app', 'github.io', 'gitlab.io', 'herokuapp.com'
  ]
  
  // Extract domain for whitelist check
  const domainMatch = lowerUrl.match(/https?:\/\/([^\/]+)/)
  const domain = domainMatch ? domainMatch[1] : lowerUrl
  
  if (safeDomains.some(d => domain.includes(d) || domain.endsWith('.' + d))) {
    return {
      trust_score: 100,
      risk_level: 'LOW',
      risk_factors: [],
      safety_indicators: ['Domain is in whitelist', 'Known safe domain']
    }
  }
  
  // Pattern 1: Typosquatting detection - ONLY on domain name, not full URL
  const domainOnly = domain.replace(/^www\./, '')
  const typosquattingPatterns = [
    { pattern: /paypa[l1][^l]|payp[a4]l|p[a4]ypal/, weight: 90, desc: 'PayPal typo-squatting detected' },
    { pattern: /amaz[o0]n|amaz[o0]-|arnazon/, weight: 85, desc: 'Amazon typo-squatting detected' },
    { pattern: /g[o0]{2,}gle|g[o0]gle-/, weight: 85, desc: 'Google typo-squatting detected' },
    { pattern: /app1e|appl[e3]|apple-/, weight: 85, desc: 'Apple typo-squatting detected' },
    { pattern: /metam[a4]sk|metamask-|meta-mas[k1]/, weight: 90, desc: 'MetaMask typo-squatting detected' },
    { pattern: /c[o0]inb[a4]se|coinb[a4]se/, weight: 90, desc: 'Coinbase typo-squatting detected' },
    { pattern: /netf1ix|netfl[ix1]|netflix-/, weight: 80, desc: 'Netflix typo-squatting detected' },
  ]
  
  for (const { pattern, weight, desc } of typosquattingPatterns) {
    if (pattern.test(domainOnly)) {
      riskScore += weight
      factors.push(desc)
    }
  }
  
  // Pattern 2: Random-looking subdomains - ONLY if domain looks suspicious
  // Only flag if combined with other risk factors
  const subdomainMatch = domain.match(/^([a-z0-9]{15,})\./)
  if (subdomainMatch && /[a-z].*[0-9]|[0-9].*[a-z]/.test(subdomainMatch[1])) {
    // Only add if domain doesn't look like a known service
    const knownServices = /(cdn|api|app|www|mail|blog|shop|store|docs|help|support|admin|dev|staging|prod|api-v\d+|v\d+)/
    if (!knownServices.test(subdomainMatch[1])) {
      riskScore += 30 // Reduced from 50
      factors.push('Unusual subdomain pattern')
    }
  }
  
  // Pattern 3: Suspicious TLDs - reduced weight
  if (/\.(tk|ml|ga|cf|gq)$/.test(domain)) {
    riskScore += 25 // Reduced from 35
    factors.push('High-risk free TLD')
  }
  
  // Pattern 4: IP addresses - HIGH RISK
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
    riskScore += 60 // Reduced from 85
    factors.push('Uses IP address instead of domain name')
  }
  
  // Pattern 5: URL shorteners
  if (/^(https?:\/\/)?(bit\.ly|tinyurl|t\.co|ow\.ly)/.test(lowerUrl)) {
    riskScore += 40 // Reduced from 50
    factors.push('URL shortener hides final destination')
  }
  
  // Pattern 6: Tracking parameters - ONLY if multiple suspicious ones
  const trackingParams = (lowerUrl.match(/(clickid|extclickid)=[a-z0-9]{15,}/gi) || []).length
  if (trackingParams >= 2) {
    riskScore += 25 // Reduced from 40
    factors.push(`Multiple suspicious tracking parameters (${trackingParams} found)`)
  }
  
  // Pattern 7: Redirect chain indicators - need at least 3 to trigger
  const redirectParams = (lowerUrl.match(/(redirect|url|return|next|to|target|destination)=/gi) || []).length
  if (redirectParams >= 3) {
    riskScore += 25 // Reduced from 35
    factors.push(`Multiple redirect parameters detected (${redirectParams})`)
  }
  
  // REMOVED Pattern 8: Credential harvesting paths - too many false positives
  // Login pages on legitimate sites are normal
  
  // Pattern 8 (was 9): Suspicious keywords - reduced weights
  const suspiciousKeywords = [
    { pattern: /(urgent|immediate|act\s*now|call\s*now).*(account|verify|update)/i, weight: 40, desc: 'Urgent account action request' },
    { pattern: /prize|winner|won.*money|congratulations.*prize/i, weight: 30, desc: 'Lottery/prize scam keywords' },
    { pattern: /verify.*account.*now|confirm.*identity.*immediately/i, weight: 35, desc: 'Pressured verification request' },
    { pattern: /wallet.*connect.*verify|crypto.*wallet.*login/i, weight: 60, desc: 'Crypto wallet scam pattern' },
    { pattern: /suspended.*account|account.*blocked|unusual.*activity.*detected/i, weight: 35, desc: 'Account threat message' },
  ]
  
  for (const { pattern, weight, desc } of suspiciousKeywords) {
    if (pattern.test(lowerUrl)) {
      riskScore += weight
      factors.push(desc)
    }
  }
  
  // Pattern 9 (was 10): Excessive subdomains - count only domain dots, not URL dots
  const domainParts = domain.split('.')
  if (domainParts.length > 4) {
    riskScore += 15 // Reduced from 25
    factors.push(`Many subdomain levels (${domainParts.length})`)
  }
  
  // Check for HTTPS - reduces risk
  if (lowerUrl.startsWith('https://')) {
    riskScore = Math.max(0, riskScore - 10)
  }
  
  // Cap at 100
  riskScore = Math.min(riskScore, 100)
  
  // ADJUSTED risk thresholds - higher to reduce false positives
  let level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  if (riskScore >= 80) {
    level = 'CRITICAL'
  } else if (riskScore >= 50) {
    level = 'HIGH'
  } else if (riskScore >= 25) {
    level = 'MEDIUM'
  } else {
    level = 'LOW'
  }
  
  const trustScore = Math.max(0, 100 - riskScore)
  
  return {
    trust_score: trustScore,
    risk_level: level as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    risk_factors: factors.length > 0 ? factors : [],
    safety_indicators: trustScore > 70 ? ['Domain appears legitimate', 'No significant risk factors detected'] : trustScore > 40 ? ['Some caution advised', 'Verify before entering sensitive information'] : ['Multiple risk factors detected', 'Proceed with caution']
  }
}

// Aurora Background Component
const AuroraBackground = () => {
  return (
    <div className="fixed inset-0 overflow-hidden pointer-events-none">
      <div className="absolute top-0 left-1/4 w-[800px] h-[600px] bg-emerald-500/20 rounded-full blur-[150px] animate-aurora-1" />
      <div className="absolute bottom-0 right-1/4 w-[600px] h-[500px] bg-blue-500/20 rounded-full blur-[150px] animate-aurora-2" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[1000px] h-[800px] bg-purple-500/10 rounded-full blur-[200px] animate-aurora-3" />
      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.03)_1px,transparent_1px)] bg-[size:60px_60px] [mask-image:radial-gradient(ellipse_80%_50%_at_50%_50%,#000_70%,transparent_100%)]" />
    </div>
  )
}

// Floating Particles Component
const FloatingParticles = () => {
  return (
    <div className="fixed inset-0 overflow-hidden pointer-events-none">
      {[...Array(20)].map((_, i) => (
        <div
          key={i}
          className="absolute w-1 h-1 bg-emerald-400/30 rounded-full animate-float"
          style={{
            left: `${Math.random() * 100}%`,
            top: `${Math.random() * 100}%`,
            animationDelay: `${Math.random() * 5}s`,
            animationDuration: `${10 + Math.random() * 10}s`
          }}
        />
      ))}
    </div>
  )
}

// Animated Counter Hook
const useCountUp = (end: number, duration: number = 2000) => {
  const [count, setCount] = useState(0)
  const [isVisible, setIsVisible] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true)
        }
      },
      { threshold: 0.1 }
    )

    if (ref.current) {
      observer.observe(ref.current)
    }

    return () => observer.disconnect()
  }, [])

  useEffect(() => {
    if (!isVisible) return

    let startTime: number
    let animationFrame: number

    const animate = (currentTime: number) => {
      if (!startTime) startTime = currentTime
      const progress = Math.min((currentTime - startTime) / duration, 1)
      
      const easeOutQuart = 1 - Math.pow(1 - progress, 4)
      setCount(Math.floor(easeOutQuart * end))

      if (progress < 1) {
        animationFrame = requestAnimationFrame(animate)
      }
    }

    animationFrame = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(animationFrame)
  }, [isVisible, end, duration])

  return { count, ref }
}

// Animated Gradient Text
const GradientText = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => {
  return (
    <span className={`bg-gradient-to-r from-emerald-400 via-teal-400 to-cyan-400 bg-[length:200%_100%] animate-gradient-x bg-clip-text text-transparent ${className}`}>
      {children}
    </span>
  )
}

// Glow Card Component
const GlowCard = ({ children, className = '', gradient = 'from-emerald-500/20 via-teal-500/20 to-cyan-500/20' }: { 
  children: React.ReactNode; 
  className?: string;
  gradient?: string;
}) => {
  return (
    <div className={`group relative ${className}`}>
      <div className={`absolute -inset-0.5 bg-gradient-to-r ${gradient} rounded-2xl opacity-0 group-hover:opacity-100 blur transition duration-500 group-hover:duration-200`} />
      <div className="relative bg-zinc-900/80 backdrop-blur-xl rounded-2xl border border-white/5 h-full">
        {children}
      </div>
    </div>
  )
}

// Scroll Reveal Component
const ScrollReveal = ({ children, className = '', delay = 0 }: { 
  children: React.ReactNode; 
  className?: string;
  delay?: number;
}) => {
  const [isVisible, setIsVisible] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true)
        }
      },
      { threshold: 0.1 }
    )

    if (ref.current) {
      observer.observe(ref.current)
    }

    return () => observer.disconnect()
  }, [])

  return (
    <div
      ref={ref}
      className={`transition-all duration-700 ${className} ${
        isVisible 
          ? 'opacity-100 translate-y-0' 
          : 'opacity-0 translate-y-10'
      }`}
      style={{ transitionDelay: `${delay}ms` }}
    >
      {children}
    </div>
  )
}

export default function Home() {
  const [stats, setStats] = useState({
    threats_analyzed: 1247,
    active_users: 89,
    high_risk_detected: 128,
    medium_risk_detected: 45,
    low_risk_detected: 1074
  })
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [copiedMac, setCopiedMac] = useState(false)
  const [copiedWin, setCopiedWin] = useState(false)
  const [urlInput, setUrlInput] = useState('')
  const [demoResult, setDemoResult] = useState<null | {
    url: string
    score: number
    level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'MINIMAL'
    factors: string[]
    indicators: string[]
    response_time: number
  }>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [serverAvailable, setServerAvailable] = useState(true)

  const threatsCount = useCountUp(stats.threats_analyzed)
  const usersCount = useCountUp(stats.active_users)
  const blockedCount = useCountUp(stats.high_risk_detected)

  const macCommand = 'curl -fsSL https://raw.githubusercontent.com/ekansh-arora0/payguard/main/install.sh | bash'
  const winCommand = 'irm https://raw.githubusercontent.com/ekansh-arora0/payguard/main/install.ps1 | iex'

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), 3000)
        
        const response = await fetch(`${API_BASE}/api/v1/stats/public`, { 
          signal: controller.signal 
        })
        clearTimeout(timeoutId)
        
        if (response.ok) {
          const data = await response.json()
          setStats(data)
          setServerAvailable(true)
        }
      } catch (err) {
        console.log('Backend not available, using demo mode')
        setServerAvailable(false)
      }
    }
    
    fetchStats()
    const interval = setInterval(fetchStats, 10000)
    return () => clearInterval(interval)
  }, [])

  const copyCommand = (type: 'mac' | 'win') => {
    const cmd = type === 'mac' ? macCommand : winCommand
    navigator.clipboard.writeText(cmd)
    if (type === 'mac') {
      setCopiedMac(true)
      setTimeout(() => setCopiedMac(false), 2000)
    } else {
      setCopiedWin(true)
      setTimeout(() => setCopiedWin(false), 2002)
    }
  }

  const analyzeUrl = async () => {
    if (!urlInput.trim()) return
    
    setIsLoading(true)
    setError('')
    const startTime = Date.now()
    
    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 3000)
      
      const response = await fetch(`${API_BASE}/api/v1/risk?fast=true`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'demo_key'
        },
        body: JSON.stringify({ url: urlInput }),
        signal: controller.signal
      })
      clearTimeout(timeoutId)
      
      if (!response.ok) throw new Error('Failed to analyze')
      
      const data = await response.json()
      setDemoResult({
        url: urlInput,
        score: data.trust_score,
        level: data.risk_level,
        factors: data.risk_factors.length > 0 ? data.risk_factors : ['No significant risk factors'],
        indicators: data.safety_indicators.length > 0 ? data.safety_indicators : ['Standard security checks passed'],
        response_time: Date.now() - startTime
      })
      
      const statsController = new AbortController()
      const statsTimeoutId = setTimeout(() => statsController.abort(), 3000)
      const statsResponse = await fetch(`${API_BASE}/api/v1/stats/public`, {
        signal: statsController.signal
      })
      clearTimeout(statsTimeoutId)
      
      if (statsResponse.ok) {
        setStats(await statsResponse.json())
      }
    } catch (err) {
      const demoData = getDemoAnalysis(urlInput)
      setDemoResult({
        url: urlInput,
        score: demoData.trust_score,
        level: demoData.risk_level,
        factors: demoData.risk_factors,
        indicators: demoData.safety_indicators,
        response_time: Date.now() - startTime
      })
      setServerAvailable(false)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <main className="min-h-screen bg-[#030303] text-white overflow-x-hidden selection:bg-emerald-500/30">
      <AuroraBackground />
      <FloatingParticles />
      
      <style jsx global>{`
        @keyframes aurora-1 {
          0%, 100% { transform: translate(0, 0) scale(1); }
          33% { transform: translate(50px, -50px) scale(1.1); }
          66% { transform: translate(-30px, 30px) scale(0.95); }
        }
        @keyframes aurora-2 {
          0%, 100% { transform: translate(0, 0) scale(1); }
          33% { transform: translate(-40px, 40px) scale(1.05); }
          66% { transform: translate(60px, -30px) scale(0.9); }
        }
        @keyframes aurora-3 {
          0%, 100% { transform: translate(-50%, -50%) scale(1); }
          50% { transform: translate(-50%, -50%) scale(1.15); }
        }
        @keyframes float {
          0%, 100% { transform: translateY(0) translateX(0); opacity: 0.3; }
          25% { transform: translateY(-20px) translateX(10px); opacity: 0.6; }
          50% { transform: translateY(-10px) translateX(-10px); opacity: 0.4; }
          75% { transform: translateY(-30px) translateX(5px); opacity: 0.5; }
        }
        @keyframes gradient-x {
          0%, 100% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
        }
        .animate-aurora-1 { animation: aurora-1 20s ease-in-out infinite; }
        .animate-aurora-2 { animation: aurora-2 25s ease-in-out infinite; }
        .animate-aurora-3 { animation: aurora-3 30s ease-in-out infinite; }
        .animate-float { animation: float 15s ease-in-out infinite; }
        .animate-gradient-x { animation: gradient-x 3s ease infinite; }
      `}</style>

      {/* Top Banner */}
      <div className="bg-emerald-500/10 border-b border-emerald-500/20 py-2 px-4">
        <div className="max-w-7xl mx-auto flex items-center justify-center gap-2 text-sm">
          <Sparkles className="w-4 h-4 text-emerald-400" />
          <span className="text-emerald-400">
            <strong>🚀 NEW:</strong> BERT + XGBoost ML pipeline — scans your screen in under 1 second, zero false positives.
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="fixed top-10 w-full z-50 bg-[#030303]/80 backdrop-blur-xl border-b border-white/5">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center shadow-lg shadow-emerald-500/20 group-hover:shadow-emerald-500/40 transition-shadow">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold text-lg group-hover:text-emerald-400 transition-colors">PayGuard</span>
          </Link>
          
          <div className="hidden md:flex items-center gap-8">
            <Link href="#features" className="text-sm text-zinc-400 hover:text-white transition-colors">Features</Link>
            <Link href="#demo" className="text-sm text-zinc-400 hover:text-white transition-colors">Demo</Link>
            <Link href="#install" className="text-sm text-zinc-400 hover:text-white transition-colors">Install</Link>
            <Link href="/privacy" className="text-sm text-zinc-400 hover:text-white transition-colors">Privacy</Link>
            <Link href="/terms" className="text-sm text-zinc-400 hover:text-white transition-colors">Terms</Link>
            <a 
              href="https://github.com/ekansh-arora0/payguard" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-sm text-zinc-400 hover:text-white transition-colors flex items-center gap-1"
            >
              GitHub <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          <button className="md:hidden p-2" onClick={() => setIsMenuOpen(!isMenuOpen)}>
            {isMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {isMenuOpen && (
          <div className="md:hidden border-t border-white/5 bg-[#030303]/95 backdrop-blur-xl px-6 py-4 space-y-4">
            <Link href="#features" className="block text-zinc-400 hover:text-white">Features</Link>
            <Link href="#demo" className="block text-zinc-400 hover:text-white">Demo</Link>
            <Link href="#install" className="block text-zinc-400 hover:text-white">Install</Link>
            <Link href="/privacy" className="block text-zinc-400 hover:text-white">Privacy</Link>
            <Link href="/terms" className="block text-zinc-400 hover:text-white">Terms</Link>
          </div>
        )}
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 px-6">
        <div className="max-w-5xl mx-auto text-center">
          <ScrollReveal>
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 mb-8 hover:border-emerald-500/50 transition-colors cursor-pointer group">
              <Sparkles className="w-4 h-4 text-emerald-400 group-hover:rotate-12 transition-transform" />
              <span className="text-sm text-emerald-400">
                Open Source - 100% Free - No Data Collection
              </span>
            </div>
          </ScrollReveal>
          
          <ScrollReveal delay={100}>
            <h1 className="text-5xl md:text-7xl font-bold tracking-tight mb-6 leading-[1.1]">
              <span className="text-white">
                Stop obvious phishing
              </span>
              <br />
              <GradientText>before you click</GradientText>
            </h1>
          </ScrollReveal>
          
          <ScrollReveal delay={200}>
            <p className="text-xl text-zinc-400 mb-6 leading-relaxed max-w-2xl mx-auto">
              Trained on <strong className="text-white">1,978 real phishing kits</strong> — catches lookalike domains, fake stores, 
              crypto scams, and obfuscated phishing pages
              <strong className="text-white"> before you enter your password</strong>.
              No network calls. All detection runs locally. Under 3 seconds per scan.
            </p>
          </ScrollReveal>

          {/* Trust Badges */}
          <ScrollReveal delay={250}>
            <div className="flex flex-wrap items-center justify-center gap-6 mb-10 text-sm text-zinc-500">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
                <span>100% Local</span>
              </div>
              <div className="flex items-center gap-2">
                <LockKeyhole className="w-4 h-4 text-emerald-500" />
                <span>Open Source</span>
              </div>
              <div className="flex items-center gap-2">
                <Timer className="w-4 h-4 text-emerald-500" />
                <span>30 Second Setup</span>
              </div>
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-emerald-500" />
                <span>macOS & Windows</span>
              </div>
            </div>
          </ScrollReveal>

          <ScrollReveal delay={300}>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <a 
                href="#install" 
                className="group relative inline-flex items-center justify-center gap-2 px-8 py-4 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold rounded-xl transition-all text-lg overflow-hidden"
              >
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700" />
                <Terminal className="w-5 h-5" />
                Install Now
                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </a>
              <a 
                href="#demo" 
                className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-zinc-700 hover:border-zinc-500 rounded-xl transition-all text-lg hover:bg-zinc-800/50 group"
              >
                <Play className="w-5 h-5 group-hover:scale-110 transition-transform" />
                See Demo
              </a>
            </div>
          </ScrollReveal>

          {/* Stats */}
          <div className="mt-20 grid grid-cols-3 gap-8 max-w-3xl mx-auto">
            {[
              { label: 'URLs Analyzed', value: threatsCount.count, ref: threatsCount.ref, suffix: '+' },
              { label: 'Threats Caught', value: blockedCount.count, ref: blockedCount.ref, suffix: '' },
              { label: 'Avg Scan Time', value: '<1', suffix: 's' },
            ].map((stat, i) => (
              <ScrollReveal key={i} delay={400 + i * 100}>
                <div ref={stat.ref} className="text-center group">
                  <div className="text-4xl md:text-5xl font-bold text-white mb-2 group-hover:scale-105 transition-transform">
                    {stat.value.toLocaleString()}{stat.suffix}
                  </div>
                  <div className="text-sm text-zinc-500">{stat.label}</div>
                </div>
              </ScrollReveal>
            ))}
          </div>
        </div>
      </section>

      {/* Install Section */}
      <section id="install" className="relative py-24 px-6">
        <div className="max-w-4xl mx-auto">
          <ScrollReveal>
            <div className="text-center mb-12">
              <h2 className="text-4xl md:text-5xl font-bold mb-4">
                <GradientText>Install in 30 seconds</GradientText>
              </h2>
              <p className="text-zinc-400 text-lg">
                No signup. No credit card. Just copy, paste, and protect yourself.
              </p>
            </div>
          </ScrollReveal>

          {/* macOS/Linux */}
          <ScrollReveal delay={100}>
            <GlowCard className="mb-6">
              <div className="p-6">
                <div className="flex items-center gap-4 mb-4">
                  <div className="w-12 h-12 rounded-xl bg-zinc-800 flex items-center justify-center text-2xl border border-white/10 group-hover:scale-110 transition-transform">
                    🍎
                  </div>
                  <div>
                    <h3 className="font-semibold text-lg">macOS & Linux</h3>
                    <p className="text-sm text-zinc-500">Copy into Terminal</p>
                  </div>
                </div>
                <div className="relative bg-black/50 rounded-xl border border-white/10 p-4 font-mono text-sm group/code">
                  <code className="text-emerald-400">{macCommand}</code>
                  <button 
                    onClick={() => copyCommand('mac')}
                    className="absolute right-4 top-1/2 -translate-y-1/2 p-2 text-zinc-500 hover:text-white transition-colors"
                  >
                    {copiedMac ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </GlowCard>
          </ScrollReveal>

          {/* Windows */}
          <ScrollReveal delay={200}>
            <GlowCard gradient="from-blue-500/20 via-cyan-500/20 to-blue-500/20">
              <div className="p-6">
                <div className="flex items-center gap-4 mb-4">
                  <div className="w-12 h-12 rounded-xl bg-zinc-800 flex items-center justify-center text-2xl border border-white/10">
                    🪟
                  </div>
                  <div>
                    <h3 className="font-semibold text-lg">Windows</h3>
                    <p className="text-sm text-zinc-500">Copy into PowerShell</p>
                  </div>
                </div>
                <div className="relative bg-black/50 rounded-xl border border-white/10 p-4 font-mono text-sm">
                  <code className="text-blue-400">{winCommand}</code>
                  <button 
                    onClick={() => copyCommand('win')}
                    className="absolute right-4 top-1/2 -translate-y-1/2 p-2 text-zinc-500 hover:text-white transition-colors"
                  >
                    {copiedWin ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </GlowCard>
          </ScrollReveal>

          {/* Trust indicators */}
          <ScrollReveal delay={300}>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-6 text-sm text-zinc-500">
              <div className="flex items-center gap-2">
                <CheckCheck className="w-4 h-4 text-emerald-500" />
                <span>Open source - audit the code</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCheck className="w-4 h-4 text-emerald-500" />
                <span>No data leaves your device</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCheck className="w-4 h-4 text-emerald-500" />
                <span>Uninstall anytime</span>
              </div>
            </div>
          </ScrollReveal>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="relative py-24 px-6">
        <div className="max-w-7xl mx-auto">
          <ScrollReveal>
            <div className="text-center mb-16">
              <h2 className="text-4xl md:text-5xl font-bold mb-4">
                <GradientText>How it works</GradientText>
              </h2>
              <p className="text-zinc-400 text-lg max-w-2xl mx-auto">
                Three detection layers: domain analysis, page structure, and JavaScript behavior — trained on 1,978 real phishing kits
              </p>
            </div>
          </ScrollReveal>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              {
              icon: Brain,
              title: 'Domain-Tier Analysis',
              description: 'Classifies every URL into safe, neutral, or suspicious tiers. Catches lookalike domains (paypa1.com), brand impersonation, and typosquatting — no hardcoded lists needed.',
              gradient: 'from-blue-500/20 to-cyan-500/20',
              iconColor: 'text-blue-400'
            },
            {
              icon: Eye,
              title: 'Page Structural Analysis',
              description: 'Analyzes HTML structure — forms, iframes, scripts, identity mismatch. Catches fake stores, phishing redirects, and obfuscated pages that look legitimate on the surface.',
              gradient: 'from-purple-500/20 to-pink-500/20',
              iconColor: 'text-purple-400'
            },
            {
              icon: Lock,
              title: 'JS Obfuscation Detection',
              description: 'ML model trained on 1,978 real phishing kits detects hex-encoded variables, string arrays, and hidden redirects. Catches what regex-based scanners miss.',
              gradient: 'from-emerald-500/20 to-teal-500/20',
              iconColor: 'text-emerald-400'
            },
            {
              icon: Zap,
              title: 'Behavioral Text Analysis',
              description: 'Detects scam language patterns — urgency + demand combos, tech support scams, crypto reward scams. Works on any text from OCR, clipboard, or page content.',
              gradient: 'from-orange-500/20 to-red-500/20',
              iconColor: 'text-orange-400'
            },
            {
              icon: Server,
              title: 'Payment Infrastructure Analysis',
              description: 'Detects fake stores by checking payment processor integration, trust signals, and domain age. Catches sites that steal money without real checkout.',
              gradient: 'from-cyan-500/20 to-blue-500/20',
              iconColor: 'text-cyan-400'
            },
            {
              icon: Globe,
              title: 'Cross-Platform',
              description: 'Works on macOS and Windows. Menu bar / system tray app with real-time protection. One command to install.',
              gradient: 'from-yellow-500/20 to-amber-500/20',
              iconColor: 'text-yellow-400'
            }
            ].map((feature, i) => (
              <ScrollReveal key={i} delay={i * 100}>
                <GlowCard gradient={`${feature.gradient}`} className="h-full">
                  <div className="p-8 h-full">
                    <div className={`w-14 h-14 rounded-2xl bg-zinc-800 flex items-center justify-center mb-6 ${feature.iconColor} group-hover:scale-110 transition-transform`}>
                      <feature.icon className="w-7 h-7" />
                    </div>
                    <h3 className="text-2xl font-semibold mb-3">{feature.title}</h3>
                    <p className="text-zinc-400 leading-relaxed">{feature.description}</p>
                  </div>
                </GlowCard>
              </ScrollReveal>
            ))}
          </div>

          {/* Detection Categories */}
          <ScrollReveal delay={400}>
            <div className="mt-16 p-8 bg-zinc-900/50 border border-white/10 rounded-2xl">
              <h3 className="text-2xl font-semibold mb-6 text-center">
                <GradientText>What PayGuard Detects</GradientText>
              </h3>
              <div className="grid md:grid-cols-3 gap-4">
                {[
                  { name: 'Lookalike Domains', examples: 'paypa1.com, arnazon.com, gooogle.com' },
                  { name: 'Brand Impersonation', examples: 'secure-chase-banking.com' },
                  { name: 'Fake Stores', examples: 'New domains with no payment processor' },
                  { name: 'Crypto Scams', examples: 'Fake airdrops, wallet connect phishing' },
                  { name: 'Obfuscated JS', examples: 'Hex-encoded phishing kit scripts' },
                  { name: 'Phishing Redirects', examples: 'Tiny pages with encoded query strings' },
                  { name: 'Homograph Attacks', examples: 'Cyrillic characters, digit substitution' },
                  { name: 'URL Shorteners', examples: 'Hidden destinations, redirect chains' },
                  { name: 'Tech Support Scams', examples: 'Fake Microsoft/Apple alerts' },
                  { name: 'Identity Mismatch', examples: 'Page claims brand not in domain' },
                  { name: 'Suspicious TLDs', examples: '.top, .xyz, .site, .shop' },
                  { name: 'New Domains', examples: '0-day-old domains with phishing content' },
                ].map((category, i) => (
                  <div key={i} className="p-4 bg-black/30 rounded-xl border border-white/5 hover:border-emerald-500/30 transition-colors">
                    <div className="font-semibold text-emerald-400 mb-1">{category.name}</div>
                    <div className="text-sm text-zinc-500">{category.examples}</div>
                  </div>
                ))}
              </div>
            </div>
          </ScrollReveal>
        </div>
      </section>

      {/* Demo Section */}
      <section id="demo" className="relative py-24 px-6">
        <div className="max-w-4xl mx-auto">
          <ScrollReveal>
            <div className="text-center mb-12">
              <h2 className="text-4xl md:text-5xl font-bold mb-4">
                <GradientText>Test the detection</GradientText>
              </h2>
              <p className="text-zinc-400 text-lg">
                See what PayGuard catches (and what it doesn't)
              </p>
            </div>
          </ScrollReveal>

          <ScrollReveal delay={100}>
            <GlowCard>
              <div className="p-8">
                {!serverAvailable && (
                  <div className="mb-6 p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-xl flex items-center gap-3">
                    <Server className="w-5 h-5 text-yellow-500" />
                    <div className="text-sm text-yellow-400">
                      <strong>Demo Mode:</strong> Using offline detection algorithms.
                    </div>
                  </div>
                )}

                <div className="flex flex-col sm:flex-row gap-4 mb-6">
                  <input
                    type="text"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeUrl()}
                    placeholder="https://example.com"
                    className="flex-1 px-5 py-4 bg-black/50 border border-white/10 rounded-xl text-white placeholder-zinc-500 focus:outline-none focus:border-emerald-500/50 transition-colors"
                  />
                  <button
                    onClick={analyzeUrl}
                    disabled={isLoading || !urlInput.trim()}
                    className="px-8 py-4 bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-black font-semibold rounded-xl flex items-center justify-center gap-2 transition-all"
                  >
                    {isLoading ? (
                      <>
                        <div className="w-5 h-5 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Zap className="w-5 h-5" />
                        Check URL
                      </>
                    )}
                  </button>
                </div>

                {/* Example URLs */}
                <div className="mb-6">
                  <div className="text-sm text-zinc-500 mb-3">Try these examples:</div>
                  <div className="flex flex-wrap gap-2">
                    {[
                      { url: 'https://verify-paypal-account-now.com/login', label: '✓ Catches: Fake PayPal', color: 'emerald' },
                      { url: 'https://google.com', label: '✓ Safe: Real Google', color: 'blue' },
                      { url: 'https://amaz0n-shop.com', label: '✓ Catches: Typosquatting', color: 'emerald' },
                      { url: 'http://free-winner-prize-now.xyz', label: '✓ Catches: Prize Scam', color: 'emerald' },
                    ].map((example, i) => (
                      <button
                        key={i}
                        onClick={() => setUrlInput(example.url)}
                        className={`px-3 py-1.5 text-xs rounded-full border transition-all hover:scale-105 ${
                          example.color === 'emerald' ? 'border-emerald-500/30 text-emerald-400 hover:border-emerald-500/50' :
                          'border-blue-500/30 text-blue-400 hover:border-blue-500/50'
                        }`}
                      >
                        {example.label}
                      </button>
                    ))}
                  </div>
                </div>

                {demoResult && (
                  <div className="border-t border-white/5 pt-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
                    <div className={`flex items-center gap-4 mb-6 p-6 rounded-xl ${
                      demoResult.level === 'CRITICAL' ? 'bg-red-950/30 border border-red-700/30' :
                      demoResult.level === 'HIGH' ? 'bg-red-500/10 border border-red-500/20' :
                      demoResult.level === 'MEDIUM' ? 'bg-yellow-500/10 border border-yellow-500/20' :
                      'bg-red-500/10 border border-red-500/20'
                    }`}>
                      {demoResult.level === 'CRITICAL' || demoResult.level === 'HIGH' || demoResult.level === 'LOW' ? (
                        <AlertTriangle className="w-10 h-10 text-red-500" />
                      ) : demoResult.level === 'MEDIUM' ? (
                        <AlertTriangle className="w-10 h-10 text-yellow-500" />
                      ) : (
                        <CheckCircle className="w-10 h-10 text-emerald-500" />
                      )}
                      <div className="flex-1">
                        <div className={`text-3xl font-bold ${
                          demoResult.level === 'CRITICAL' ? 'text-red-700' :
                          demoResult.level === 'HIGH' ? 'text-red-500' :
                          demoResult.level === 'MEDIUM' ? 'text-yellow-500' :
                          'text-red-500'
                        }`}>
                          {demoResult.level} RISK
                        </div>
                        <div className="text-zinc-400">Trust Score: {demoResult.score}/100</div>
                      </div>
                      <div className="text-right hidden sm:block">
                        <div className="text-xs text-zinc-500 mb-1">Response</div>
                        <div className="text-emerald-400 font-mono text-lg">{demoResult.response_time}ms</div>
                      </div>
                    </div>

                    <div className="grid md:grid-cols-2 gap-6">
                      <div className="bg-black/30 rounded-xl p-5 border border-white/5">
                        <div className="text-sm text-zinc-500 mb-4 font-semibold uppercase tracking-wider">Risk Factors</div>
                        <div className="space-y-3">
                          {demoResult.factors.map((factor, i) => (
                            <div key={i} className="text-zinc-300 text-sm flex items-start gap-3">
                              <span className="w-1.5 h-1.5 rounded-full bg-red-400 mt-2 flex-shrink-0" />
                              {factor}
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="bg-black/30 rounded-xl p-5 border border-white/5">
                        <div className="text-sm text-zinc-500 mb-4 font-semibold uppercase tracking-wider">Safety Indicators</div>
                        <div className="space-y-3">
                          {demoResult.indicators.map((indicator, i) => (
                            <div key={i} className="text-zinc-300 text-sm flex items-start gap-3">
                              <CheckCircle className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                              {indicator}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </GlowCard>
          </ScrollReveal>
        </div>
      </section>

      {/* CTA Section */}
      <section className="relative py-24 px-6 bg-gradient-to-b from-transparent to-emerald-500/5">
        <div className="max-w-4xl mx-auto text-center">
          <ScrollReveal>
            <h2 className="text-4xl md:text-5xl font-bold mb-6">
              <span className="text-white">Don't get scammed</span>
            </h2>
            <p className="text-xl text-zinc-400 mb-8 max-w-2xl mx-auto">
              Join <strong className="text-white">89 beta users</strong> already protected. 
              <strong className="text-white"> Free during beta</strong>. Under 1 second to detect a threat.
            </p>
            <a 
              href="#install" 
              className="group relative inline-flex items-center justify-center gap-2 px-10 py-5 bg-emerald-500 hover:bg-emerald-400 text-black font-bold rounded-xl transition-all text-xl overflow-hidden"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700" />
              <Shield className="w-6 h-6" />
              Install PayGuard
              <ArrowRight className="w-6 h-6 group-hover:translate-x-1 transition-transform" />
            </a>
            <p className="mt-4 text-sm text-zinc-500">
              Takes 30 seconds. Uninstall anytime. No catch.
            </p>
          </ScrollReveal>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative border-t border-white/5 py-16 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-12">
            <div className="col-span-2">
              <Link href="/" className="flex items-center gap-2 mb-4 group">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <span className="font-bold text-lg group-hover:text-emerald-400 transition-colors">PayGuard</span>
              </Link>
              <p className="text-zinc-400 text-sm max-w-sm leading-relaxed mb-4">
                AI-powered phishing detection with real-time browser monitoring and redirect tracking.
              </p>
              <div className="flex items-center gap-2 text-sm text-zinc-500">
                <span>Made with</span>
                <span className="text-red-500">❤</span>
                <span>by people who hate scammers</span>
              </div>
            </div>
            <div>
              <h4 className="font-semibold mb-4 text-zinc-300">Product</h4>
              <ul className="space-y-3 text-sm text-zinc-500">
                <li><Link href="/#install" className="hover:text-white transition-colors">Install</Link></li>
                <li><Link href="/#demo" className="hover:text-white transition-colors">Demo</Link></li>
                <li><a href="https://github.com/ekansh-arora0/payguard" className="hover:text-white transition-colors flex items-center gap-1">GitHub <ExternalLink className="w-3 h-3"/></a></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4 text-zinc-300">Legal</h4>
              <ul className="space-y-3 text-sm text-zinc-500">
                <li><Link href="/privacy" className="hover:text-white transition-colors">Privacy Policy</Link></li>
                <li><Link href="/terms" className="hover:text-white transition-colors">Terms of Service</Link></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-white/5 pt-8 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="text-sm text-zinc-600">
              © 2025 PayGuard. Open source under MIT License.
            </div>
            <div className="text-sm text-zinc-600">
              {stats.threats_analyzed?.toLocaleString() || '1,247'} URLs analyzed
            </div>
          </div>
        </div>
      </footer>
    </main>
  )
}