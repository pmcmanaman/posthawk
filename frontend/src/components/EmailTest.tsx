import { useState } from 'react';

export function EmailTest() {
  const [email, setEmail] = useState('');
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await fetch('/api/check-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      setResult(data.message);
    } catch (error) {
      setResult('Error checking email');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="email-test">
      <h2>Email Test</h2>
      <form onSubmit={handleSubmit}>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Enter email"
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Checking...' : 'Check Email'}
        </button>
      </form>
      {result && <p>Result: {result}</p>}
    </div>
  );
}
