/**
 * cleaner.js
 * 移植自 Cleaner.c (JS Cleaner V8)
 * 功能：
 * 1. 自动识别并彻底删除“整行注释”，不留空行
 * 2. 修复 Unexpected token, 保护 https://, 智能处理 console
 * 3. 自动清理注释前的缩进空格
 */

const fs = require('fs');

// 定义状态常量
const STATE = {
    CODE: 0,
    STRING_SQ: 1,    // '...'
    STRING_DQ: 2,    // "..."
    STRING_TMP: 3,   // `...`
    REGEX: 4,        // /.../
    COMMENT_LINE: 5, // //...
    COMMENT_BLOCK: 6 // /*...*/
};

// 辅助函数：判断字符是否为空白
function isSpace(char) {
    return /\s/.test(char);
}

// 辅助函数：判断字符是否为字母数字或 _$
function isAlnum(char) {
    return /[a-zA-Z0-9_$]/.test(char);
}

// 判断 / 是否为正则开头 (移植自 is_regex_start)
function isRegexStart(text, idx) {
    let i = idx - 1;
    while (i >= 0 && isSpace(text[i])) i--;
    if (i < 0) return true;
    const last = text[i];
    if ("(=,:!&|?{};,".includes(last)) return true;
    
    if (isAlnum(last) || last === ')') {
        let end = i;
        while (i >= 0 && isAlnum(text[i])) i--;
        const word = text.substring(i + 1, end + 1);
        
        const keywords = ["return", "case", "throw", "delete", "void", "typeof", "await", "yield"];
        if (keywords.includes(word)) return true;
        
        return false;
    }
    return false;
}

// 检查 console 类型 (移植自 check_console_type)
// 返回: 0=无, 1=调用 console.log(...), 2=引用 console.log
function checkConsoleType(text, i, size) {
    if (text.substring(i, i + 8) !== "console.") return { type: 0, len: 0 };
    
    const methods = ["log", "warn", "error", "info", "debug"];
    let matched = false;
    let mLen = 0;
    
    for (const method of methods) {
        if (text.substring(i + 8, i + 8 + method.length) === method) {
            const nextChar = text[i + 8 + method.length];
            if (!isAlnum(nextChar)) { // 确保匹配完整单词
                matched = true;
                mLen = 8 + method.length;
                break;
            }
        }
    }
    
    if (!matched) return { type: 0, len: 0 };
    
    let j = i + mLen;
    while (j < size && isSpace(text[j])) j++;
    
    if (j < size && text[j] === '(') return { type: 1, len: mLen };
    return { type: 2, len: mLen };
}

function processCode(input) {
    const size = input.length;
    const output = []; // 使用数组作为缓冲区
    let state = STATE.CODE;
    let i = 0;
    
    let skipMode = false;
    let parenDepth = 0;
    let inArgStr = 0; // 0=none, 1=', 2=", 3=`
    let isWholeLineComment = false;

    while (i < size) {
        const c = input[i];
        const next = (i + 1 < size) ? input[i + 1] : '';

        // --- Console 参数吞噬模式 ---
        if (skipMode) {
            if (inArgStr !== 0) {
                if (c === '\\') { i++; } // 跳过转义
                else if ((inArgStr === 1 && c === '\'') ||
                         (inArgStr === 2 && c === '"') ||
                         (inArgStr === 3 && c === '`')) {
                    inArgStr = 0;
                }
            } else {
                if (c === '\'') inArgStr = 1;
                else if (c === '"') inArgStr = 2;
                else if (c === '`') inArgStr = 3;
                else if (c === '(') parenDepth++;
                else if (c === ')') {
                    parenDepth--;
                    if (parenDepth === 0) skipMode = false;
                }
            }
            i++;
            continue;
        }

        // --- 正常模式 ---
        if (state === STATE.CODE) {
            const { type: cType, len: mLen } = checkConsoleType(input, i, size);
            
            if (cType === 1) { // console.log(...) 调用
                const rep = "void(0)";
                for (const char of rep) output.push(char);
                i += mLen;
                while (i < size && isSpace(input[i])) i++;
                if (input[i] === '(') {
                    skipMode = true;
                    parenDepth = 1;
                    i++;
                }
                continue;
            } else if (cType === 2) { // console.log 引用
                const rep = "(()=>{})";
                for (const char of rep) output.push(char);
                i += mLen;
                continue;
            }

            if (c === '\'') { state = STATE.STRING_SQ; output.push(c); }
            else if (c === '"') { state = STATE.STRING_DQ; output.push(c); }
            else if (c === '`') { state = STATE.STRING_TMP; output.push(c); }
            else if (c === '/') {
                if (next === '/') {
                    // --- 核心改进：检测是否为整行注释 ---
                    // 回溯检查 output 缓冲区
                    let tempIdx = output.length;
                    let onlySpaces = true;
                    
                    while (tempIdx > 0) {
                        const prev = output[tempIdx - 1];
                        if (prev === '\n' || prev === '\r') break; // 到了上一行末尾
                        if (prev !== ' ' && prev !== '\t') {
                            onlySpaces = false;
                            break;
                        }
                        tempIdx--;
                    }

                    if (onlySpaces) {
                        // 是整行注释，回退指针（删除之前的缩进空格）
                        output.length = tempIdx;
                        isWholeLineComment = true;
                    } else {
                        isWholeLineComment = false;
                    }

                    state = STATE.COMMENT_LINE;
                    i++; // 跳过下一个 '/'
                } else if (next === '*') {
                    state = STATE.COMMENT_BLOCK;
                    i++; // 跳过 '*'
                } else {
                    if (isRegexStart(input, i)) state = STATE.REGEX;
                    output.push(c);
                }
            } else {
                output.push(c);
            }
        }
        // --- 字符串 / 正则 ---
        else if (state === STATE.STRING_SQ) {
            output.push(c);
            if (c === '\\') { if (next) { output.push(next); i++; } }
            else if (c === '\'') state = STATE.CODE;
        }
        else if (state === STATE.STRING_DQ) {
            output.push(c);
            if (c === '\\') { if (next) { output.push(next); i++; } }
            else if (c === '"') state = STATE.CODE;
        }
        else if (state === STATE.STRING_TMP) {
            output.push(c);
            if (c === '\\') { if (next) { output.push(next); i++; } }
            else if (c === '`') state = STATE.CODE;
        }
        else if (state === STATE.REGEX) {
            output.push(c);
            if (c === '\\') { if (next) { output.push(next); i++; } }
            else if (c === '/') state = STATE.CODE;
            else if (c === '\n') state = STATE.CODE; // 防止正则跑出当前行
        }
        // --- 注释处理 (带空行清理) ---
        else if (state === STATE.COMMENT_LINE) {
            if (c === '\n') {
                if (!isWholeLineComment) {
                    output.push(c); // 行尾注释，保留换行
                }
                // 如果是整行注释，不写入 c (\n)，相当于整行删除
                state = STATE.CODE;
                isWholeLineComment = false;
            }
        }
        else if (state === STATE.COMMENT_BLOCK) {
            if (c === '*' && next === '/') {
                state = STATE.CODE;
                output.push(' '); // 用空格代替块注释，防止粘连
                i++;
            } else if (c === '\n') {
                output.push(c); // 保留块注释内的换行，维持行号一致性
            }
        }
        i++;
    }

    return output.join('');
}

function cleanFile(filePath) {
    try {
        if (!fs.existsSync(filePath)) {
            console.error(`[Cleaner] File not found: ${filePath}`);
            return;
        }
        console.log(`[Cleaner] Processing: ${filePath} ...`);
        const content = fs.readFileSync(filePath, 'utf8');
        const cleaned = processCode(content);
        fs.writeFileSync(filePath, cleaned, 'utf8');
        console.log(`[Cleaner] Done. Removed comments and consoles.`);
    } catch (e) {
        console.error(`[Cleaner] Error: ${e.message}`);
    }
}

module.exports = { cleanFile };
