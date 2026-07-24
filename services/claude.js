const axios = require('axios');

async function askClaude(systemPrompt, userPrompt) {
  try {
    const response = await axios.post(
      'https://api.groq.com/openai/v1/chat/completions',
      {
        model: 'llama-3.1-8b-instant',
        max_tokens: 700,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ]
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.GROQ_API_KEY}`
        },
        timeout: 10000
      }
    );

    return response.data.choices[0].message.content.trim();

  } catch (error) {
    console.error('Groq API error:', error.message);
    return 'AI analysis unavailable (timeout or network error).';
  }
}

module.exports = { askClaude };

