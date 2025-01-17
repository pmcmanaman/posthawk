const form = document.getElementById('emailForm');
if (form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    const resultDiv = document.getElementById('result');
    
    try {
      const response = await fetch('/v1/check-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ email })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        resultDiv.textContent = data.valid ? 'Valid email' : 'Invalid email';
        resultDiv.style.color = data.valid ? 'green' : 'red';
      } else {
        throw new Error(data.message || 'Validation failed');
      }
    } catch (error) {
      resultDiv.textContent = error.message;
      resultDiv.style.color = 'red';
    }
  });
}
