<?php
declare(strict_types=1);

// Локальная подготовка: включение возможно только по отдельному разрешению.
const CONTACT_ENABLED = false;
const MAX_REQUEST_BYTES = 131072;
const MAIL_TO = 'privacy@chestny-ai.ru';
const MAIL_FROM = 'privacy@chestny-ai.ru';

ini_set('display_errors', '0');

function respond(int $status, string $message): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode(['message' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

// Не писать исходные предупреждения PHP с возможными данными в error log.
set_error_handler(static function (int $severity): bool {
    throw new RuntimeException('Internal processing error');
});

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        header('Allow: POST');
        respond(405, 'Метод не поддерживается.');
    }
    // Блокировка действует и при обходе disabled/JavaScript посетителем.
    if (!CONTACT_ENABLED) {
        respond(503, 'Приём обращений через форму пока отключён.');
    }
    if (($_SERVER['QUERY_STRING'] ?? '') !== '' || !empty($_FILES)) {
        respond(400, 'Недопустимый формат запроса.');
    }
    $contentType = strtolower(trim($_SERVER['CONTENT_TYPE'] ?? ''));
    if (!preg_match('/\Aapplication\/x-www-form-urlencoded(?:\s*;\s*charset=utf-8)?\z/', $contentType)) {
        respond(415, 'Недопустимый формат запроса.');
    }
    $declaredLength = $_SERVER['CONTENT_LENGTH'] ?? null;
    if ($declaredLength !== null && (!ctype_digit((string) $declaredLength) || (float) $declaredLength > MAX_REQUEST_BYTES)) {
        respond(413, 'Запрос превышает допустимый размер.');
    }
    // Ограниченное чтение; нельзя доверять только Content-Length или $_POST.
    $raw = file_get_contents('php://input', false, null, 0, MAX_REQUEST_BYTES + 1);
    if ($raw === false) {
        respond(400, 'Не удалось прочитать запрос.');
    }
    if (strlen($raw) > MAX_REQUEST_BYTES) {
        respond(413, 'Запрос превышает допустимый размер.');
    }
    $expected = ['name', 'email', 'message', 'personal-data-consent', 'consent-version'];
    $fields = [];
    // Собственный строгий разбор сохраняет видимость повторных ключей.
    // PHP parse_str/$_POST могут перезаписывать их и преобразовывать имена.
    foreach (explode('&', $raw) as $pair) {
        if ($pair === '' || strpos($pair, '=') === false || preg_match('/%(?![0-9a-fA-F]{2})/', $pair)) {
            respond(400, 'Недопустимые параметры формы.');
        }
        [$key, $value] = explode('=', $pair, 2);
        $key = urldecode($key);
        $value = urldecode($value);
        if (!in_array($key, $expected, true) || array_key_exists($key, $fields)) {
            respond(400, 'Недопустимые параметры формы.');
        }
        if (!is_string($value) || preg_match('//u', $value) !== 1) {
            respond(400, 'Некорректная кодировка формы.');
        }
        // name[], email[x] и другие формы массивов не входят в expected.
        $fields[$key] = $value;
    }
    if (count($fields) !== count($expected)) {
        respond(422, 'Заполните обязательные поля и подтвердите согласие.');
    }
    if ($fields['personal-data-consent'] !== '1') {
        respond(422, 'Для отправки необходимо согласие на обработку персональных данных.');
    }
    $consent = json_decode(file_get_contents(__DIR__ . '/../legal/PD-CONSENT-2026-09-15.json'), true, 512, JSON_THROW_ON_ERROR);
    if (($consent['version'] ?? '') !== 'PD-CONSENT-2026-09-15' || $fields['consent-version'] !== $consent['version']) {
        respond(422, 'Обновите страницу и ознакомьтесь с действующей версией согласия.');
    }
    // Даже снятие выключателя не активирует ещё не введённую редакцию.
    $effectiveAt = $consent['effectiveAt'] ?? null;
    if (!is_string($effectiveAt) || !preg_match('/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/', $effectiveAt)) {
        respond(503, 'Приём обращений через форму пока отключён.');
    }
    $effectiveDate = DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s\Z', $effectiveAt, new DateTimeZone('UTC'));
    $dateErrors = DateTimeImmutable::getLastErrors();
    if ($effectiveDate === false
        || ($dateErrors !== false && ($dateErrors['warning_count'] > 0 || $dateErrors['error_count'] > 0))
        || $effectiveDate->format('Y-m-d\TH:i:s\Z') !== $effectiveAt
        || $effectiveDate->getTimestamp() > time()) {
        respond(503, 'Приём обращений через форму пока отключён.');
    }
    $name = preg_replace('/\A\s+|\s+\z/u', '', $fields['name']);
    $email = trim($fields['email']);
    $normalizedMessage = str_replace(["\r\n", "\r"], "\n", $fields['message']);
    if (preg_match('//u', $normalizedMessage) !== 1) {
        respond(400, 'Некорректная кодировка формы.');
    }
    $message = preg_replace('/\A\s+|\s+\z/u', '', $normalizedMessage);
    // UTF-16 units align with HTML maxlength without requiring mbstring.
    $length = static function (string $value): int {
        preg_match_all('/./us', $value, $characters);
        $units = 0;
        foreach ($characters[0] as $character) {
            $units += strlen($character) === 4 ? 2 : 1;
        }
        return $units;
    };
    if ($name === '' || $length($fields['name']) > 100 || preg_match('/[\x00-\x1F\x7F]/', $fields['name'])) {
        respond(422, 'Проверьте имя: от 1 до 100 символов, без управляющих символов.');
    }
    if ($email === '' || strlen($fields['email']) > 254 || preg_match('/[\x00-\x20\x7F]/', $fields['email'])
        || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        respond(422, 'Укажите корректный адрес электронной почты.');
    }
    if ($message === '' || $length($normalizedMessage) > 5000 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $normalizedMessage)) {
        respond(422, 'Проверьте сообщение: от 1 до 5000 символов.');
    }
    $id = bin2hex(random_bytes(16));
    $acceptedAt = gmdate('Y-m-d\TH:i:s\Z');
    $body = "Обращение с chestny-ai.ru\n"
        . "ID: " . $id . "\n"
        . "Серверное время UTC: " . $acceptedAt . "\n"
        . "Версия согласия: " . $consent['version'] . "\n"
        . "accepted=true\n\n"
        . "Имя: " . $name . "\n"
        . "Email: " . $email . "\n\n"
        . "Сообщение:\n" . $message;
    $headers = [
        'From' => MAIL_FROM,
        'Reply-To' => $email,
        'MIME-Version' => '1.0',
        'Content-Type' => 'text/plain; charset=UTF-8',
        'Content-Transfer-Encoding' => 'base64',
    ];
    // Только четыре аргумента: пользовательские значения не идут в shell.
    $sent = mail(MAIL_TO, 'chestny-ai.ru contact ' . $id, chunk_split(base64_encode($body), 76, "\r\n"), $headers);
    unset($raw, $fields, $name, $email, $message, $body, $headers);
    if (!$sent) {
        respond(503, 'Не удалось передать обращение на отправку. Попробуйте позже.');
    }
    respond(202, 'Обращение передано на отправку.');
} catch (Throwable $error) {
    // Без дампа запроса, текста исключения, адреса отправителя и stack trace.
    respond(503, 'Не удалось обработать обращение. Попробуйте позже.');
}
