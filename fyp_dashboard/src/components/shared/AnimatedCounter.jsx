import { useState, useEffect } from 'react'

// Animated Counter Component
const AnimatedCounter = ({ end, duration = 2000 }) => {
  const [count, setCount] = useState(0)
  
  useEffect(() => {
    let startTime
    const animate = (currentTime) => {
      if (!startTime) startTime = currentTime
      const progress = Math.min((currentTime - startTime) / duration, 1)
      setCount(Math.floor(progress * end))
      if (progress < 1) {
        requestAnimationFrame(animate)
      }
    }
    requestAnimationFrame(animate)
  }, [end, duration])
  
  return <span>{count}</span>
}

export default AnimatedCounter
