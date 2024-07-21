package saphy.saphy.global.exception;

import lombok.Getter;

@Getter
public class SaphyException extends RuntimeException {

	private final ErrorCode errorCode;
	private String message;

	private SaphyException(ErrorCode errorCode) {
		super(errorCode.getMessage());
		this.errorCode = errorCode;
	}

	private SaphyException(ErrorCode errorCode, String message) {
		super(message);
		this.errorCode = errorCode;
		this.message = message;
	}

	public static SaphyException from(ErrorCode errorCode) {
		return new SaphyException(errorCode);
	}

	public static SaphyException from(ErrorCode errorCode, String message) {
		return new SaphyException(errorCode, message);
	}

}