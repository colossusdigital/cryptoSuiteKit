export class KeyValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyValidationError';
  }
}