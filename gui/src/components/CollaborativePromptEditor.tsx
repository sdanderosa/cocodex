import { useMemo, useState, type CSSProperties, type TextareaHTMLAttributes } from "react";
import {
  buildPromptOverlayParts,
  promptPresenceColor,
  type RemotePromptEditorPresence,
} from "../cocodex-prompt-overlay-state";

type Props = Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "value"> & {
  value: string;
  remotePresence: RemotePromptEditorPresence[];
};

export function CollaborativePromptEditor({
  value,
  remotePresence,
  className,
  onScroll,
  ...textareaProps
}: Props) {
  const [scroll, setScroll] = useState({ left: 0, top: 0 });
  const parts = useMemo(
    () => buildPromptOverlayParts(value, remotePresence),
    [value, remotePresence],
  );

  const hasRemoteCaret = remotePresence.some(member => member.caret);
  return <div className={`cocodex-prompt-editor${hasRemoteCaret ? " has-remote-presence" : ""}`}>
    <textarea {...textareaProps} value={value} className={className}
      onScroll={event => {
        setScroll({ left: event.currentTarget.scrollLeft, top: event.currentTarget.scrollTop });
        onScroll?.(event);
      }} />
    {hasRemoteCaret && <div className="cocodex-prompt-overlay" aria-hidden="true">
      <div className="cocodex-prompt-overlay-content" style={{
        transform: `translate(${-scroll.left}px, ${-scroll.top}px)`,
      }}>
        {parts.map(part => <span key={`${part.start}:${part.end}`} className="cocodex-prompt-overlay-part"
          data-selected={part.selectedBy.length > 0 ? "true" : undefined}
          data-selection-count={part.selectedBy.length || undefined}
          style={part.selectedBy.length > 0 ? {
            "--cocodex-presence-color": promptPresenceColor(part.selectedBy[0].deviceId),
          } as CSSProperties : undefined}>
          {part.carets.map(member => <span key={member.deviceId} className="cocodex-prompt-remote-caret"
            style={{ "--cocodex-presence-color": promptPresenceColor(member.deviceId) } as CSSProperties}>
            <span className="cocodex-prompt-remote-label">{member.displayName}{member.typing ? " · typing" : ""}</span>
          </span>)}
          {part.text}
        </span>)}
      </div>
    </div>}
  </div>;
}
