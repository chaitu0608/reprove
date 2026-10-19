"use client";

import { useState } from "react";

// Renders user comments as raw HTML (XSS flaw)
export default function CommentBox({ comments }: { comments: { author: string; body: string }[] }) {
  return (
    <div>
      {comments.map((c, i) => (
        <div key={i} className="comment">
          <strong>{c.author}</strong>
          <div dangerouslySetInnerHTML={{ __html: c.body }} />
        </div>
      ))}
    </div>
  );
}

export function NewComment({ onAdd }: { onAdd: (body: string) => void }) {
  const [text, setText] = useState("");
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onAdd(text);
      }}
    >
      <textarea value={text} onChange={(e) => setText(e.target.value)} />
      <button type="submit">Post</button>
    </form>
  );
}
