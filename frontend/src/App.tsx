import { AuthProvider } from './context/AuthContext'
import { EmailTest } from './components/EmailTest'

function App() {
  return (
    <AuthProvider>
      <EmailTest />
    </AuthProvider>
  )
}

export default App
