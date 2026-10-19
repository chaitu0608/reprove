"use client";

import { useState } from "react";

// The LLM is called straight from the browser with a NEXT_PUBLIC_ key (ai + secret flaw).
// Anyone can read the key in devtools and burn the quota (or worse).
export default function ChatBox() {
  const [messages, setMessages] = useState<string[]>([]);
  const [input, setInput] = useState("");

  async function send() {
    const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${key}`,
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: input }],
      }),
    });
    const data = await res.json();
    setMessages((m) => [...m, data.choices?.[0]?.message?.content ?? ""]);
  }

  return (
    <div>
      <ul>
        {messages.map((m, i) => (
          <li key={i}>{m}</li>
        ))}
      </ul>
      <input value={input} onChange={(e) => setInput(e.target.value)} />
      <button onClick={send}>Send</button>
    </div>
  );
}
