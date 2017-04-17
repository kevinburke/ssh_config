package ssh_config

import (
	"fmt"
	"strings"
)

type sshParser struct {
	flow          chan token
	config        *Config
	tokensBuffer  []token
	currentTable  []string
	seenTableKeys []string
}

type sshParserStateFn func() sshParserStateFn

// Formats and panics an error message based on a token
func (p *sshParser) raiseError(tok *token, msg string, args ...interface{}) {
	panic(tok.Position.String() + ": " + fmt.Sprintf(msg, args...))
}

func (p *sshParser) run() {
	for state := p.parseStart; state != nil; {
		state = state()
	}
}

func (p *sshParser) peek() *token {
	if len(p.tokensBuffer) != 0 {
		return &(p.tokensBuffer[0])
	}

	tok, ok := <-p.flow
	if !ok {
		return nil
	}
	p.tokensBuffer = append(p.tokensBuffer, tok)
	return &tok
}

func (p *sshParser) getToken() *token {
	if len(p.tokensBuffer) != 0 {
		tok := p.tokensBuffer[0]
		p.tokensBuffer = p.tokensBuffer[1:]
		return &tok
	}
	tok, ok := <-p.flow
	if !ok {
		return nil
	}
	return &tok
}

func (p *sshParser) parseStart() sshParserStateFn {
	tok := p.peek()

	// end of stream, parsing is finished
	if tok == nil {
		return nil
	}

	switch tok.typ {
	case tokenComment, tokenEmptyLine:
		return p.parseComment
	case tokenKey:
		return p.parseKV
	case tokenEOF:
		return nil
	default:
		p.raiseError(tok, fmt.Sprintf("unexpected token %q\n", tok))
	}
	return nil
}

func (p *sshParser) parseKV() sshParserStateFn {
	key := p.getToken()
	p.assume(tokenString)
	val := p.getToken()
	comment := ""
	tok := p.peek()
	if tok.typ == tokenComment && tok.Position.Line == val.Position.Line {
		tok = p.getToken()
		comment = tok.val
	}
	if key.val == "Host" {
		patterns := strings.Split(val.val, " ")
		for i := range patterns {
			if patterns[i] == "" {
				patterns = append(patterns[:i], patterns[i+1:]...)
			}
		}
		p.config.Hosts = append(p.config.Hosts, &Host{
			Patterns:   patterns,
			Nodes:      make([]Node, 0),
			EOLComment: comment,
		})
		return p.parseStart
	}
	lastHost := p.config.Hosts[len(p.config.Hosts)-1]
	kv := &KV{
		Key:          key.val,
		Value:        val.val,
		Comment:      comment,
		leadingSpace: uint16(key.Position.Col) - 1,
		position:     key.Position,
	}
	lastHost.Nodes = append(lastHost.Nodes, kv)
	return p.parseStart
}

func (p *sshParser) parseComment() sshParserStateFn {
	comment := p.getToken()
	lastHost := p.config.Hosts[len(p.config.Hosts)-1]
	lastHost.Nodes = append(lastHost.Nodes, &Empty{
		Comment: comment.val,
		// account for the "#" as well
		leadingSpace: comment.Position.Col - 2,
		position:     comment.Position,
	})
	return p.parseStart
}

// assume peeks at the next token and ensures it's the right type
func (p *sshParser) assume(typ tokenType) {
	tok := p.peek()
	if tok == nil {
		p.raiseError(tok, "was expecting token %s, but token stream is empty", tok)
	}
	if tok.typ != typ {
		p.raiseError(tok, "was expecting token %s, but got %s instead", typ, tok)
	}
}

func parseSSH(flow chan token) *Config {
	result := newConfig()
	result.position = Position{1, 1}
	parser := &sshParser{
		flow:          flow,
		config:        result,
		tokensBuffer:  make([]token, 0),
		currentTable:  make([]string, 0),
		seenTableKeys: make([]string, 0),
	}
	parser.run()
	return result
}
