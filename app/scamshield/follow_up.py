"""Bounded, session-owned continuation of a completed risk analysis."""

from collections import OrderedDict
from dataclasses import dataclass, field
import re
from threading import Lock
from time import monotonic

from .request import URL


MAX_QUESTIONS = 3
FOLLOW_UP_SECONDS = 20 * 60

INFORMATION = {
    "id_photo": "신분증 사진",
    "otp": "인증번호",
    "credentials": "비밀번호·계정 정보",
    "payment": "돈이나 송금",
    "install": "앱 설치·원격 제어",
    "other": "기타",
    "none": "아무것도 요구하지 않았어요",
    "unsure": "잘 모르겠어요",
}
REQUEST_PATTERNS = {
    "id_photo": r"신분증\s*(?:사진|사본|촬영).{0,20}(?:요구|요청|보내|제출|올리)",
    "otp": r"(?:인증\s*번호|OTP).{0,20}(?:요구|요청|보내|알려|입력)",
    "credentials": r"비밀번호.{0,20}(?:요구|요청|보내|알려|입력)",
    "payment": r"(?:송금|입금).{0,20}(?:요구|요청|하세요|해\s*달)",
    "install": r"(?:앱\s*설치|원격\s*제어).{0,20}(?:요구|요청|하세요|해\s*달)",
}
CONTEXT_CUES = re.compile(r"사칭|본인\s*확인|신원\s*확인|채용\s*담당자라(?:는|고)|사기일|피싱일|스미싱일|수상|의심")
NEGATED_REQUEST = re.compile(r"말라|하지\s*마|지\s*마세요|없었|않았|않습")

INFORMATION_ACTIONS = {
    "id_photo": "신분증 사진을 보내지 마세요. 공식 창구에 본인 확인이 필요한지 따로 확인하세요.",
    "otp": "인증번호는 전달하지 마세요. 본인이 시작한 인증이 아니라면 진행을 멈추세요.",
    "credentials": "비밀번호나 계정 정보를 입력하지 마세요. 기관의 공식 앱이나 홈페이지에서 직접 확인하세요.",
    "payment": "송금하기 전에 공식 연락처로 요청과 계좌가 맞는지 확인하세요.",
    "install": "상대가 보낸 앱을 설치하거나 원격 제어를 허용하지 마세요.",
    "other": "요청받은 정보나 행동이 공식 절차에 해당하는지 먼저 확인하세요.",
}
CALL_REQUESTS = {"transfer": ("payment",), "code": ("otp", "credentials"),
                 "id_photo": ("id_photo",), "app": ("install",), "other": ()}
CALL_VERIFICATION = {"no": "not_checked", "yes": "confirmed", "denied": "denied"}


@dataclass
class FollowUp:
    link: bool
    verdict: str
    known_requests: tuple[str, ...]
    phone: bool = False
    known_source: str | None = None
    known_interaction: str | None = None
    answers: dict[str, str] = field(default_factory=dict)
    skipped: bool = False
    last_submission: tuple[str, str] | None = None

    def next_question(self):
        if self.skipped or len(self.answers) >= MAX_QUESTIONS:
            return None
        interaction = self.answers.get("interaction", self.known_interaction)
        if interaction in {"paid", "installed"}:
            return None
        if interaction == "shared" and (self.known_requests or "requested_info" in self.answers):
            return None
        order = ["interaction", "requested_info", "source"] if self.link or self.known_requests else [
            "requested_info", "interaction", "source",
        ]
        for key in order:
            if key in self.answers:
                continue
            if key == "requested_info" and (self.known_requests or self.link and interaction == "no_action"):
                continue
            if key == "source" and (interaction == "shared" or self.known_source is not None):
                continue
            return key
        return None

    def options(self, key):
        if key == "requested_info":
            return INFORMATION
        if key == "interaction":
            no_action = ("아직 열거나 응답하지 않았어요" if self.link
                         else "통화에서 요청받은 행동은 하지 않았어요" if self.phone else "아직 응답하지 않았어요")
            viewed = "링크를 열기만 했어요" if self.link else "통화만 했어요" if self.phone else "답장만 했어요"
            return {
                "no_action": no_action,
                "viewed": viewed,
                "shared": "정보를 입력하거나 보냈어요",
                "paid": "이미 돈을 보냈어요",
                "installed": "앱을 설치했거나 원격 제어를 허용했어요",
                "unsure": "잘 모르겠어요",
            }
        return {
            "confirmed": "원래 알던 번호나 공식 채널에서 같은 요청을 확인했어요",
            "denied": "공식 채널에 물어보니 그런 요청을 하지 않았대요",
            "not_checked": "아직 따로 확인하지 않았어요",
            "unsure": "잘 모르겠어요",
        }

    def guidance(self):
        interaction = self.answers.get("interaction", self.known_interaction)
        requests = self.known_requests or (self.answers.get("requested_info"),)
        if interaction == "paid":
            return ["추가 송금을 멈추고, 송금에 사용한 은행이나 결제 서비스의 공식 고객센터에 즉시 연락하세요."]
        if interaction == "installed":
            return ["원격 제어를 끊고 해당 기기에서 금융 앱을 사용하지 마세요. 다른 기기로 기관의 공식 고객센터에 문의하세요."]
        if interaction == "shared":
            if "id_photo" in requests:
                return ["추가 전송을 멈추고, 신분증을 발급한 기관의 공식 창구에 노출 사실을 알려 필요한 조치를 확인하세요."]
            if {"otp", "credentials"} & set(requests):
                return ["공식 앱이나 홈페이지에서 비밀번호를 변경하고, 해당 기관의 고객센터에 계정 보호를 요청하세요."]
            return ["추가로 정보를 보내지 마세요. 정보를 보낸 사실을 해당 서비스의 공식 고객센터에 알려 보호 조치를 확인하세요."]
        actions = [INFORMATION_ACTIONS[request] for request in requests if request in INFORMATION_ACTIONS]
        source = self.answers.get("source", self.known_source)
        if source == "denied":
            actions.insert(0, "공식 경로에서 해당 요청을 부인했어요. 그 번호로 다시 전화하거나 상대의 요청에 응하지 마세요."
                           if self.phone else "공식 경로에서 해당 요청을 부인했어요. 상대에게 더 응답하거나 링크를 열지 마세요.")
        elif source == "confirmed":
            actions.append("같은 요청을 확인했더라도 민감한 정보는 통화로 전달하지 말고 공식 절차를 이용하세요."
                           if self.phone else "같은 요청을 확인했더라도 받은 링크 대신 공식 앱이나 홈페이지에서 직접 진행하세요.")
        elif self.answers:
            actions.append("상대가 알려준 번호 대신, 기존에 저장한 번호나 직접 찾은 공식 연락처로 요청을 확인하세요."
                           if self.phone else "메시지에 적힌 링크나 연락처 대신, 직접 찾은 공식 연락처로 요청을 확인하세요.")
        return actions

    def view(self):
        key = self.next_question()
        question = None
        if key:
            prompts = {
                "requested_info": "통화에서 요구한 정보 중 기억나는 게 있나요?" if self.phone else "상대나 링크에서 어떤 정보나 행동을 요구했나요?",
                "interaction": ("링크를 받은 뒤 어떤 행동을 하셨나요?" if self.link
                                else "통화 중이나 통화가 끝난 뒤 어떤 행동을 하셨나요?" if self.phone
                                else "요청을 받은 뒤 어떤 행동을 하셨나요?"),
                "source": "기존에 알던 번호나 공식 채널로 같은 요청인지 따로 확인했나요?",
            }
            question = {"id": key, "prompt": prompts[key],
                        "options": [{"id": value, "label": label} for value, label in self.options(key).items()]}
        return {
            "status": "skipped" if self.skipped else "asking" if key else "completed",
            "question": question, "answered_count": len(self.answers), "max_questions": MAX_QUESTIONS,
            "actions": self.guidance(), "original_verdict": self.verdict,
        }


class FollowUpSessions:
    """Keep choices and verified context in memory, never the original message or URL."""

    def __init__(self):
        self._lock = Lock()
        self._items = OrderedDict()

    def start(self, owner, result, target_type, text, *, call_context=None):
        if target_type not in {"url", "text"}:
            return None
        verdict = result["status"]
        link = "conditions" in result
        content = URL.sub("", text)
        context = (result.get("text_assessment") or {}).get("context") or result.get("message_context") or {}
        eligible = verdict in {"KNOWN_RISK", "SUSPICIOUS", "INSUFFICIENT_EVIDENCE"} or (
            verdict == "NO_KNOWN_MATCH" and context.get("signals")
        )
        known = tuple(key for key, pattern in REQUEST_PATTERNS.items()
                      if any(not NEGATED_REQUEST.search(match.group()) for match in re.finditer(pattern, content)))
        if call_context is not None:
            checked = call_context["verification"]
            sent = call_context["already_sent"]
            known = CALL_REQUESTS[call_context["request"]] or known
            item = FollowUp(False, verdict, known, phone=True, known_source=CALL_VERIFICATION[checked],
                            known_interaction="paid" if sent else None)
        else:
            text_concern = result.get("local_signals") or context.get("signals") or CONTEXT_CUES.search(content)
            if not eligible or not (link or target_type == "text" and text_concern):
                return None
            item = FollowUp(link, verdict, known)
        with self._lock:
            now = monotonic()
            while self._items and (len(self._items) >= 1024 or next(iter(self._items.values()))[0] <= now):
                self._items.popitem(last=False)
            self._items[(owner, result["run_id"])] = (now + FOLLOW_UP_SECONDS, item)
        return item.view()

    def answer(self, owner, run_id, question_id, answer):
        with self._lock:
            key = (owner, run_id)
            entry = self._items.get(key)
            if entry is None or entry[0] <= monotonic():
                self._items.pop(key, None)
                raise LookupError("follow-up not available")
            item = entry[1]
            if item.last_submission == (question_id, answer):
                return item.view()
            expected = item.next_question()
            if expected != question_id:
                raise ValueError("question not current")
            if answer == "skip":
                item.skipped = True
            elif answer in item.options(expected):
                item.answers[expected] = answer
            else:
                raise ValueError("answer not available")
            item.last_submission = (question_id, answer)
            return item.view()
