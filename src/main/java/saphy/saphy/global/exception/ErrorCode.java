package saphy.saphy.global.exception;

import org.springframework.http.HttpStatus;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum ErrorCode {
	// member
	MEMBER_NOT_AUTHENTICATED(HttpStatus.UNAUTHORIZED, "로그인하지 않은 사용자입니다"),
	MEMBER_NOT_FOUND(HttpStatus.NOT_FOUND, "사용자 정보가 존재하지 않습니다"),
	INCORRECT_PASSWORD(HttpStatus.UNAUTHORIZED, "비밀번호가 일치하지 않습니다"),
	INCORRECT_AUTH_INFO(HttpStatus.UNAUTHORIZED, "아이디 또는 비밀번호가 일치하지 않습니다"),
	DUPLICATE_MEMBER_EMAIL(HttpStatus.CONFLICT, "중복된 이메일입니다"),
	DUPLICATE_MEMBER_LOGIN_ID(HttpStatus.CONFLICT, "중복된 로그인 아이디입니다"),
	DUPLICATE_MEMBER_NICKNAME(HttpStatus.CONFLICT, "중복된 닉네임입니다"),
	DUPLICATE_MEMBER_PHONE_NUMBER(HttpStatus.CONFLICT, "중복된 전화번호입니다"),

	// auth
	EXPIRED_AUTH_TOKEN(HttpStatus.UNAUTHORIZED, "만료된 로그인 토큰입니다."),
	INVALID_AUTH_TOKEN(HttpStatus.UNAUTHORIZED, "올바르지 않은 로그인 토큰입니다."),
	NOT_BEARER_TOKEN_TYPE(HttpStatus.UNAUTHORIZED, "Bearer 타입의 토큰이 아닙니다."),
	NEED_AUTH_TOKEN(HttpStatus.UNAUTHORIZED, "로그인이 필요한 서비스입니다."),
	INCORRECT_PASSWORD_OR_ACCOUNT(HttpStatus.UNAUTHORIZED, "비밀번호가 틀렸거나, 해당 계정이 없습니다."),
	ACCOUNT_USERNAME_EXIST(HttpStatus.UNAUTHORIZED, "해당 계정이 존재합니다."),
	NOT_FOUND_REFRESH_TOKEN(HttpStatus.BAD_REQUEST,"쿠키에 refresh token 을 찾아올 수 없습니다"),
	INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "존재하지 않은 리프래쉬 토큰으로 재발급 요청을 했습니다."),
	EXPIRED_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "만료된 리프래쉬 토큰입니다."),
	OAUTH2_PROVIDER_NOT_RESPONSE(HttpStatus.INTERNAL_SERVER_ERROR, "OAuth2 제공자 서버에 문제가 발생했습니다."),
	OAUTH2_INVALID_REQUEST(HttpStatus.INTERNAL_SERVER_ERROR, "알 수 없는 OAuth2 에러가 발생했습니다."),
	OPEN_ID_PROVIDER_NOT_RESPONSE(HttpStatus.INTERNAL_SERVER_ERROR, "OpenID 제공자 서버에 문제가 발생했습니다."),

	// transaction
	TRANSACTION_NOT_FOUND(HttpStatus.NOT_FOUND, "존재하지 않는 거래입니다."),
	TRANSACTION_ALREADY_EXIST(HttpStatus.CONFLICT, "이미 존재하는 거래입니다."),
	TRANSACTION_NOT_AUTHORIZED(HttpStatus.FORBIDDEN, "해당 거래에 권한이 없습니다."),
	TRANSACTION_EXPIRED(HttpStatus.BAD_REQUEST, "거래 기간이 만료되었습니다."),
	TRANSACTION_INVALID_STATUS(HttpStatus.BAD_REQUEST, "유효하지 않은 거래 상태입니다."),
	TRANSACTION_PAYMENT_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "결제 처리에 실패했습니다."),
	TRANSACTION_SHIPPING_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "배송 처리에 실패했습니다."),
	TRANSACTION_CANCEL_NOT_ALLOWED(HttpStatus.FORBIDDEN, "거래를 취소할 수 없습니다."),
	TRANSACTION_REFUND_NOT_ALLOWED(HttpStatus.FORBIDDEN, "환불을 처리할 수 없습니다."),
	TRANSACTION_ITEM_NOT_RECEIVED(HttpStatus.BAD_REQUEST, "상품이 수령되지 않았습니다."),
	TRANSACTION_ITEM_DAMAGED(HttpStatus.BAD_REQUEST, "상품이 손상되었습니다."),
	TRANSACTION_INVALID_QUANTITY(HttpStatus.BAD_REQUEST, "유효하지 않은 수량입니다."),
	TRANSACTION_DUPLICATE_REQUEST(HttpStatus.CONFLICT, "중복된 거래 요청입니다."),
	TRANSACTION_INVALID_PAYMENT_METHOD(HttpStatus.BAD_REQUEST, "유효하지 않은 결제 방법입니다."),
	TRANSACTION_ADDRESS_NOT_FOUND(HttpStatus.NOT_FOUND, "배송 주소를 찾을 수 없습니다."),
	TRANSACTION_DELIVERY_DELAYED(HttpStatus.INTERNAL_SERVER_ERROR, "배송이 지연되었습니다."),
	TRANSACTION_SELLER_NOT_RESPONSIVE(HttpStatus.INTERNAL_SERVER_ERROR, "판매자가 응답하지 않습니다."),
	TRANSACTION_BUYER_NOT_RESPONSIVE(HttpStatus.INTERNAL_SERVER_ERROR, "구매자가 응답하지 않습니다."),
	TRANSACTION_INSUFFICIENT_FUNDS(HttpStatus.PAYMENT_REQUIRED, "잔액이 부족합니다."),

	// item
	ITEM_NOT_FOUND(HttpStatus.NOT_FOUND, "존재하지 않는 제품입니다."),
	ITEM_ALREADY_EXIST(HttpStatus.CONFLICT, "이미 존재하는 제품입니다."),
	ITEM_NOT_AVAILABLE(HttpStatus.BAD_REQUEST, "해당 제품은 현재 거래할 수 없습니다."),
	ITEM_INVALID_CONDITION(HttpStatus.BAD_REQUEST, "유효하지 않은 제품 상태입니다."),
	ITEM_PRICE_TOO_HIGH(HttpStatus.BAD_REQUEST, "제품 가격이 너무 높습니다."),
	ITEM_PRICE_TOO_LOW(HttpStatus.BAD_REQUEST, "제품 가격이 너무 낮습니다."),
	ITEM_DESCRIPTION_TOO_LONG(HttpStatus.BAD_REQUEST, "제품 설명이 너무 깁니다."),
	ITEM_IMAGE_TOO_LARGE(HttpStatus.BAD_REQUEST, "제품 이미지가 너무 큽니다."),
	ITEM_CATEGORY_INVALID(HttpStatus.BAD_REQUEST, "유효하지 않은 제품 카테고리입니다."),
	ITEM_OUT_OF_STOCK(HttpStatus.BAD_REQUEST, "제품이 재고가 없습니다."),
	ITEM_COLOR_NOT_AVAILABLE(HttpStatus.BAD_REQUEST, "해당 색상의 제품이 재고가 없습니다."),
	ITEM_SIZE_NOT_AVAILABLE(HttpStatus.BAD_REQUEST, "해당 사이즈의 제품이 재고가 없습니다."),
	ITEM_MODEL_NOT_AVAILABLE(HttpStatus.BAD_REQUEST, "해당 모델의 제품이 재고가 없습니다."),
	ITEM_DISCONTINUED(HttpStatus.BAD_REQUEST, "단종된 제품입니다."),

	// chat
	CHAT_NOT_FOUND(HttpStatus.NOT_FOUND, "존재하지 않는 채팅방입니다."),
	CHAT_ALREADY_EXIST(HttpStatus.CONFLICT, "이미 존재하는 채팅방입니다."),
	CHAT_NOT_AUTHORIZED(HttpStatus.FORBIDDEN, "채팅방에 가입되어 있지 않습니다."),
	CHAT_ALREADY_JOINED(HttpStatus.CONFLICT, "이미 가입된 채팅방입니다."),
	CHATROOM_NOT_ALLOWED(HttpStatus.FORBIDDEN, "채팅방에 접근할 수 없습니다."),
	CHAT_NOT_AVAILABLE(HttpStatus.FORBIDDEN, "메시지를 보낼 수 없습니다."),
	NOT_ALLOWED_TO_DELETE_CHATROOM(HttpStatus.FORBIDDEN, "채팅방을 삭제할 수 없습니다."),

	// others
	REQUEST_OK(HttpStatus.OK, "올바른 요청입니다."),

	INVALID_REQUEST(HttpStatus.BAD_REQUEST, "올바르지 않은 요청입니다."),
	NOT_ENOUGH_PERMISSION(HttpStatus.FORBIDDEN, "해당 권한이 없습니다."),
	INTERNAL_SEVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버 에러가 발생하였습니다. 관리자에게 문의해 주세요."),
	FOR_TEST_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "테스트용 에러입니다.");

	private final HttpStatus status;
	private final String message;
}
