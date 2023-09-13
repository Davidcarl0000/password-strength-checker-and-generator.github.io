// Array of common bad passwords
const commonBadPasswords = [
    "password", "123456", "qwerty", "admin", "12345", "123456", "123456789", "test1",
    "password", "12345678", "zinch", "g_czechout", "asdf", "qwerty", "1234567890",
    "1234567", "Aa123456.", "iloveyou", "1234", "abc123", "111111", "123123", "dubsmash",
    "test", "princess", "qwertyuiop", "sunshine", "BvtTest123", "11111", "ashley",
    "00000", "000000", "password1", "monkey", "livetest", "55555", "soccer", "charlie",
    "asdfghjkl", "654321", "family", "michael", "123321", "football", "baseball",
    "q1w2e3r4t5y6", "nicole", "jessica", "purple", "shadow", "hannah", "chocolate",
    "michelle", "daniel", "maggie", "qwerty123", "hello", "112233", "jordan", "tigger",
    "666666", "987654321", "superman", "12345678910", "summer", "1q2w3e4r5t", "fitness",
    "bailey", "zxcvbnm", "fuckyou", "121212", "buster", "butterfly", "dragon",
    "jennifer", "amanda", "justin", "cookie", "basketball", "shopping", "pepper",
    "joshua", "hunter", "ginger", "matthew", "abcd1234", "taylor", "samantha", "whatever",
    "andrew", "1qaz2wsx3edc", "thomas", "jasmine", "animoto", "madison", "987654321",
    "54321", "flower", "Password", "maria", "babygirl", "lovely", "sophie", "Chegg123",
    "computer", "qwe123", "anthony", "1q2w3e4r", "peanut", "bubbles", "asdasd", "qwert",
    "1qaz2wsx", "pakistan", "123qwe", "liverpool", "elizabeth", "harley", "chelsea",
    "familia", "yellow", "william", "george", "7777777", "loveme", "123abc", "letmein",
    "oliver", "batman", "cheese", "banana", "testing", "secret", "angel", "friends",
    "jackson", "aaaaaa", "softball", "chicken", "lauren", "andrea", "welcome", "asdfgh",
    "robert", "orange", "Testing1", "pokemon", "555555", "melissa", "morgan", "123123123",
    "qazwsx", "diamond", "brandon", "jesus", "mickey", "olivia", "changeme", "danielle",
    "victoria", "gabriel", "123456a", "0.00000000", "loveyou", "hockey", "freedom",
    "azerty", "snoopy", "skinny", "myheritage", "qwerty1", "159753", "forever", "iloveu",
    "killer", "joseph", "master", "mustang", "hellokitty", "school", "Password1",
    "patrick", "blink182", "tinkerbell", "rainbow", "nathan", "cooper", "onedirection",
    "alexander", "jordan23", "lol123", "jasper", "junior", "q1w2e3r4", "222222",
    "11111111", "benjamin", "jonathan", "passw0rd", "123456789", "a123456", "samsung",
    "123", "love123", "123456", "123456789", "picture1", "password", "12345678", "111111",
    "123123", "12345", "1234567890", "senha", "1234567", "qwerty", "abc123", "Million2",
    "000000", "1234", "iloveyou", "aaron431", "password1", "qqww1122", "123", "omgpop",
    "123321", "654321", "qwertyuiop", "qwer123456", "123456a", "a123456", "666666",
    "asdfghjkl", "ashley", "987654321", "unknown", "zxcvbnm", "112233", "chatbooks",
    "20100728", "123123123", "princess",     "jacket025", "evite", "123abc", "123qwe", "sunshine", "121212", "dragon", "1q2w3e4r",
    "5201314", "159753", "123456789", "pokemon", "qwerty123", "Bangbang123", "jobandtalent",
    "monkey", "1qaz2wsx", "abcd1234", "default", "aaaaaa", "soccer", "123654", "ohmnamah23",
    "12345678910", "zing", "shadow", "102030", "11111111", "asdfgh", "147258369", "qazwsx",
    "qwe123", "michael", "football", "baseball", "1q2w3e4r5t", "party", "daniel", "asdasd",
    "222222", "myspace1", "asd123", "555555", "a123456789", "888888", "7777777", "fuckyou",
    "1234qwer", "superman", "147258", "999999", "159357", "love123", "tigger", "purple",
    "samantha", "charlie", "babygirl", "88888888", "jordan23", "789456123", "jordan", "anhyeuem",
    "killer", "basketball", "michelle", "1q2w3e", "lol123", "qwerty1", "789456", "6655321",
    "nicole", "naruto", "master", "chocolate", "maggie", "computer", "hannah", "jessica",
    "123456789a", "password123", "hunter", "686584", "iloveyou1", "987654321", "justin",
    "cookie", "hello", "blink182", "andrew", "25251325", "love", "987654", "bailey", "princess1",
    "123456", "101010", "12341234", "a801016", "1111", "1111111", "anthony", "yugioh",
    "fuckyou1", "amanda", "asdf1234", "trustno1", "butterfly", "x4ivygA51F", "iloveu", "batman",
    "starwars", "summer", "michael1", "00000000", "lovely", "jakcgt333", "buster", "jennifer",
    "babygirl1", "family", "456789", "azerty", "andrea", "q1w2e3r4", "qwer1234", "hello123",
    "10203", "matthew", "pepper", "12345a", "letmein", "joshua", "131313", "123456b", "madison",
    "Sample123", "777777", "football1", "jesus1", "taylor", "b123456", "whatever", "welcome",
    "ginger", "flower", "333333", "1111111111", "robert", "samsung", "a12345", "loveme",
    "gabriel", "alexander", "cheese", "passw0rd", "142536", "peanut", "11223344", "thomas",
    "angel1", "123456", "123456789", "12345", "qwerty", "password", "12345678", "111111",
    "123123", "1234567890", "1234567", "qwerty123", "000000", "1q2w3e", "aa12345678",
    "abc123", "password1", "1234", "qwertyuiop", "123321", "password123", "1q2w3e4r5t",
    "iloveyou", "654321", "666666", "987654321", "123", "123456a", "qwe123", "1q2w3e4r",
    "7777777", "1qaz2wsx", "123qwe", "zxcvbnm", "121212", "asdasd", "a123456", "555555",
    "dragon", "112233", "123123123", "monkey", "11111111", "qazwsx", "159753", "asdfghjkl",
    "222222", "1234qwer", "qwerty1", "123654", "123abc", "asdfgh", "777777", "aaaaaa",
    "myspace1", "88888888", "fuckyou", "123456789a", "999999", "888888", "football", "princess",
    "789456123", "147258369", "1111111", "sunshine", "michael", "computer", "qwer1234",
    "daniel", "789456", "11111", "abcd1234", "q1w2e3r4", "shadow", "159357", "123456q",
    "1111", "samsung", "killer", "asd123", "superman", "master", "12345a", "azerty",
    "zxcvbn", "qazwsxedc", "131313", "ashley", "target123", "987654", "baseball", "qwert",
    "asdasd123", "qwerty", "soccer", "charlie", "qweasdzxc", "tinkle", "jessica", "q1w2e3r4t5",
    "asdf", "test1", "1g2w3e4r", "gwerty123", "zag12wsx", "gwerty", "147258", "12341234",
    "qweqwe", "jordan", "pokemon", "q1w2e3r4t5y6", "12345678910", "1111111111", "12344321",
    "thomas", "love", "12qwaszx", "102030", "welcome", "liverpool", "iloveyou1", "michelle",
    "101010", "1234561", "hello", "andrew", "a123456789", "a12345", "Status", "fuckyou1",
    "1qaz2wsx3edc", "hunter", "princess1", "naruto", "justin", "jennifer", "qwerty12",
    "qweasd", "anthony", "andrea", "joshua", "asdf1234", "12345qwert", "1qazxsw2", "marina",
    "love123", "111222", "robert", "10203", "nicole", "letmein", "football1", "secret",
    "1234554321", "freedom", "michael1", "11223344", "qqqqqq", "123654789", "chocolate", "12345q", "internet", "q1w2e3", "google",
    "starwars", "mynoob", "qwertyui", "55555", "qwertyu", "lol123", "lovely", "monkey1",
    "nikita", "pakistan", "7758521", "87654321", "147852", "jordan23", "212121", "123789",
    "147852369", "123456789q", "qwe", "forever", "741852963", "123qweasd", "123456abc",
    "1q2w3e4r5t6y", "qazxsw", "456789", "232323", "999999999", "qwerty12345", "qwaszx",
    "1234567891", "456123", "444444", "qq123456", "xxx"
    // Add more bad passwords here
];

function checkPasswordStrength(password) {
    function containsSpecialCharacters(password) {
        const specialCharacters = "!@#$%^&*()_-+=<>?/";
        for (const char of password) {
            if (specialCharacters.includes(char)) {
                return true;
            }
        }
        return false;
    }

    function containsNumbers(password) {
        for (const char of password) {
            if (!isNaN(parseInt(char))) {
                return true;
            }
        }
        return false;
    }

    function containsLowercaseLetters(password) {
        for (const char of password) {
            if (char === char.toLowerCase() && char !== char.toUpperCase()) {
                return true;
            }
        }
        return false;
    }

    function containsUppercaseLetters(password) {
        for (const char of password) {
            if (char === char.toUpperCase() && char !== char.toLowerCase()) {
                return true;
            }
        }
        return false;
    }

    // Check if the password is in the list of common bad passwords
    if (commonBadPasswords.includes(password.toLowerCase())) {
        return "Very Weak";  // Password is in the list of common bad passwords
    } else if (password.length < 8) {
        return "Weak";  // Password is too short
    } else if (
        containsSpecialCharacters(password) &&
        containsNumbers(password) &&
        containsLowercaseLetters(password) &&
        containsUppercaseLetters(password)
    ) {
        return "Strong";  // Password meets all criteria
    } else {
        return "Moderate";  // Password is moderately strong
    }
}

function generateRandomPassword(length) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?/";
    let password = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        password += charset.charAt(randomIndex);
    }
    return password;
}

async function checkPassword() {
    const password = document.getElementById('password').value;
    const result = document.getElementById('result');
    
    // Call isCommonBadPassword and await the result
    const isCommonPassword = await isCommonBadPassword(password);

    if (isCommonPassword) {
        result.style.color = "red";
        result.textContent = "Password strength: Very Weak (Common Bad Password)";
    } else {
        const strength = checkPasswordStrength(password);
        
        if (strength === "Weak" || strength === "Moderate") {
            result.style.color = "orange";
        } else {
            result.style.color = "green";
        }

        result.textContent = `Password strength: ${strength}`;
    }
}


function generatePassword() {
    const length = parseInt(prompt("Enter the password length:"));
    const generatedPassword = generateRandomPassword(length);
    document.getElementById('password').value = generatedPassword;
    checkPassword();
}

function copyToClipboard() {
    const generatedPassword = document.getElementById('password').value;
    
    // Create a temporary input element
    const tempInput = document.createElement('input');
    
    // Set its value to the generated password
    tempInput.value = generatedPassword;
    
    // Append the input element to the document
    document.body.appendChild(tempInput);
    
    // Select the text in the input element
    tempInput.select();
    
    // Copy the selected text to the clipboard
    document.execCommand('copy');
    
    // Remove the temporary input element
    document.body.removeChild(tempInput);
    
    alert('Password copied to clipboard!');
}


function toggleDarkMode() {
    const container = document.getElementById('container');
    const body = document.body;

    if (body.classList.contains('light')) {
        body.classList.remove('light');
        body.classList.add('dark');
        container.classList.remove('light');
        container.classList.add('dark');
    } else {
        body.classList.remove('dark');
        body.classList.add('light');
        container.classList.remove('dark');
        container.classList.add('light');
    }
}

function togglePasswordVisibility() {
    const passwordInput = document.getElementById('password');
    const showPasswordCheckbox = document.getElementById('showPassword');

    if (showPasswordCheckbox.checked) {
        passwordInput.type = 'text';
    } else {
        passwordInput.type = 'password';
    }
}

async function isCommonBadPassword(password) {
    // Hash the password using SHA-1
    const hash = await sha1(password);

    // Send a request to the HIBP API
    const response = await fetch(`https://api.pwnedpasswords.com/range/${hash.substring(0, 5)}`);

    // Check if the response status code is 200 (OK)
    if (response.status === 200) {
        const hashes = await response.text();

        // Split the response into lines and check if the hash prefix is in the response
        const hashSuffix = hash.substring(5).toUpperCase();
        return hashes.includes(hashSuffix);
    }

    // If the response status is not 200, return false
    return false;
}

async function checkPasswordStrength(password) {
    const isCommonPassword = await isCommonBadPassword(password);

    if (isCommonPassword) {
        return "Very Weak";  // Password is in the list of common bad passwords
    } else if (password.length < 8) {
        return "Weak";  // Password is too short
    } else {
        return "Strong";  // Password meets all criteria
    }
}



// Helper function to compute SHA-1 hash
async function sha1(str) {
    const buffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}
