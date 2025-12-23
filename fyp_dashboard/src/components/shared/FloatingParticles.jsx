import { useState, useEffect } from 'react'

// Floating Particles Component
const FloatingParticles = () => {
  const [particles, setParticles] = useState([])
  
  useEffect(() => {
    const newParticles = Array.from({ length: 20 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() * 4 + 1,
      opacity: Math.random() * 0.5 + 0.1,
      animationDelay: Math.random() * 20
    }))
    setParticles(newParticles)
  }, [])
  
  return (
    <div className="floating-particles">
      {particles.map(particle => (
        <div
          key={particle.id}
          className="particle"
          style={{
            left: `${particle.x}%`,
            top: `${particle.y}%`,
            width: `${particle.size}px`,
            height: `${particle.size}px`,
            opacity: particle.opacity,
            animationDelay: `${particle.animationDelay}s`
          }}
        />
      ))}
    </div>
  )
}

export default FloatingParticles
